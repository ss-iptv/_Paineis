import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional, Set
from datetime import datetime
import requests
from requests.exceptions import RequestException
import time
from pathlib import Path
import concurrent.futures
import threading
from urllib3.exceptions import InsecureRequestWarning
import warnings
from enum import Enum
from abc import ABC, abstractmethod

# Suppress SSL warnings more elegantly
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

class LoggerSetup:
    """Centralized logging configuration"""
    @staticmethod
    def setup():
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('app.log'),
                logging.StreamHandler()
            ]
        )
        # Suppress noisy loggers
        logging.getLogger('urllib3').setLevel(logging.ERROR)
        return logging.getLogger(__name__)

logger = LoggerSetup.setup()

class LoginStatus(Enum):
    """Enumeration of possible login states"""
    SUCCESS = "success"
    INVALID_CREDENTIALS = "invalid_credentials"
    CONNECTION_ERROR = "connection_error"
    UNKNOWN_ERROR = "unknown_error"

@dataclass
class Config:
    """Application configuration with type hints and validation"""
    max_workers: int = 20
    request_timeout: int = 15
    retry_delay: int = 2
    max_retries: int = 3
    verify_ssl: bool = False
    delay_between_requests: float = 1.0
    max_consecutive_errors: int = 3
    reconnect_delay: int = 2
    session_renewal_time: int = 300
    
    def __post_init__(self):
        """Validate configuration values"""
        if self.max_workers < 1:
            raise ValueError("max_workers must be positive")
        if self.request_timeout < 1:
            raise ValueError("request_timeout must be positive")
        if self.retry_delay < 0:
            raise ValueError("retry_delay cannot be negative")

@dataclass
class Credentials:
    """Login credentials"""
    username: str
    password: str
    
    def __post_init__(self):
        if not self.username or not self.password:
            raise ValueError("Username and password cannot be empty")

@dataclass
class LoginResult:
    """Login attempt result with enhanced status tracking"""
    status: LoginStatus
    site: str
    credentials: Credentials
    session_id: Optional[str] = None
    credits: Optional[str] = None
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def success(self) -> bool:
        return self.status == LoginStatus.SUCCESS

class ResultManager:
    """Thread-safe result management"""
    def __init__(self):
        self._results: List[LoginResult] = []
        self._results_lock = threading.Lock()
        self._success_combinations: Set[tuple] = set()
        self._combinations_lock = threading.Lock()
        self._consecutive_errors = 0
        self._errors_lock = threading.Lock()

    def add_result(self, result: LoginResult) -> None:
        with self._results_lock:
            self._results.append(result)
            
        if result.success:
            with self._combinations_lock:
                self._success_combinations.add(
                    (result.credentials.username, result.credentials.password)
                )
            self.reset_errors()
        else:
            self.increment_errors()

    def increment_errors(self) -> None:
        with self._errors_lock:
            self._consecutive_errors += 1

    def reset_errors(self) -> None:
        with self._errors_lock:
            self._consecutive_errors = 0

    @property
    def consecutive_errors(self) -> int:
        with self._errors_lock:
            return self._consecutive_errors

class LoginClient:
    """HTTP client for login operations with session management"""
    def __init__(self, config: Config):
        self.config = config
        self._session = None
        self._session_created = None
        self._create_session()

    def _create_session(self) -> None:
        """Create a new session with security headers"""
        self._session = requests.Session()
        self._session.verify = self.config.verify_ssl
        self._session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        self._session_created = datetime.now()

    def _check_session_renewal(self) -> None:
        """Renew session if expired"""
        if (datetime.now() - self._session_created).seconds > self.config.session_renewal_time:
            self._create_session()
            logger.info("Session renewed")

    def login(self, site: str, credentials: Credentials) -> LoginResult:
        """Attempt login with retry logic"""
        self._check_session_renewal()
        url = f"https://{site}/sys/api.php"

        for attempt in range(self.config.max_retries):
            try:
                response = self._session.post(
                    url,
                    data={
                        "action": "login",
                        "username": credentials.username,
                        "password": credentials.password
                    },
                    timeout=self.config.request_timeout
                )
                
                if response.ok and "success\":true" in response.text:
                    return LoginResult(
                        status=LoginStatus.SUCCESS,
                        site=site,
                        credentials=credentials,
                        session_id=response.cookies.get("PHPSESSID")
                    )
                
                return LoginResult(
                    status=LoginStatus.INVALID_CREDENTIALS,
                    site=site,
                    credentials=credentials,
                    error_message="Invalid credentials"
                )

            except RequestException as e:
                logger.warning(f"Connection error on attempt {attempt + 1}: {str(e)}")
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (2 ** attempt))  # Exponential backoff
                    continue
                
                return LoginResult(
                    status=LoginStatus.CONNECTION_ERROR,
                    site=site,
                    credentials=credentials,
                    error_message=f"Connection error after {self.config.max_retries} attempts"
                )
            
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
                return LoginResult(
                    status=LoginStatus.UNKNOWN_ERROR,
                    site=site,
                    credentials=credentials,
                    error_message=str(e)
                )
            
            finally:
                time.sleep(self.config.delay_between_requests)

class FileHandler(ABC):
    """Abstract base class for file operations"""
    @abstractmethod
    def load(self, path: Path) -> List:
        pass
    
    @abstractmethod
    def save(self, data: any, path: Path) -> None:
        pass

class SiteLoader(FileHandler):
    """Handle site list file operations"""
    def load(self, path: Path) -> List[str]:
        try:
            sites = path.read_text(encoding='utf-8').splitlines()
            return [site.strip() for site in sites if site.strip()]
        except Exception as e:
            logger.error(f"Error loading sites: {e}")
            return []

    def save(self, sites: List[str], path: Path) -> None:
        try:
            path.write_text('\n'.join(sites), encoding='utf-8')
        except Exception as e:
            logger.error(f"Error saving sites: {e}")

class CredentialsLoader(FileHandler):
    """Handle credentials file operations"""
    def load(self, path: Path) -> List[Credentials]:
        credentials = []
        try:
            for line in path.read_text(encoding='utf-8').splitlines():
                if ':' in line:
                    username, password = line.strip().split(':', 1)
                    if username and password:
                        credentials.append(Credentials(username, password))
        except Exception as e:
            logger.error(f"Error loading credentials: {e}")
        return credentials

    def save(self, credentials: List[Credentials], path: Path) -> None:
        try:
            lines = [f"{c.username}:{c.password}" for c in credentials]
            path.write_text('\n'.join(lines), encoding='utf-8')
        except Exception as e:
            logger.error(f"Error saving credentials: {e}")

class LoginManager:
    """Orchestrate the login verification process"""
    def __init__(self, config: Config):
        self.config = config
        self.result_manager = ResultManager()
        self._progress_lock = threading.Lock()
        self.total_attempts = 0
        self.completed_attempts = 0
        self.running = True
        self.last_activity = time.time()

    def _worker(self, site: str, credentials: Credentials) -> None:
        """Worker function for processing a single login attempt"""
        if not self.running:
            return

        client = LoginClient(self.config)
        
        try:
            if self.result_manager.consecutive_errors >= self.config.max_consecutive_errors:
                logger.warning(f"Too many consecutive errors. Waiting {self.config.reconnect_delay}s...")
                time.sleep(self.config.reconnect_delay)
                self.result_manager.reset_errors()

            result = client.login(site, credentials)
            self.result_manager.add_result(result)
            self._update_progress()
            
        except Exception as e:
            logger.error(f"Worker error: {str(e)}")
        finally:
            with self._progress_lock:
                self.completed_attempts += 1
                self.last_activity = time.time()

    def _update_progress(self) -> None:
        """Update and display progress"""
        with self._progress_lock:
            progress = (self.completed_attempts / self.total_attempts) * 100
            logger.info(f"Progress: {progress:.1f}% ({self.completed_attempts}/{self.total_attempts})")

    def process_sites(self, sites: List[str], credentials: List[Credentials]) -> None:
        """Process all sites and credentials concurrently"""
        self.total_attempts = len(sites) * len(credentials)
        self.completed_attempts = 0
        start_time = time.time()

        logger.info(f"Starting verification of {len(sites)} sites with {len(credentials)} credentials")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {
                executor.submit(self._worker, site, cred): (site, cred)
                for site in sites
                for cred in credentials
            }
            
            try:
                concurrent.futures.wait(futures, return_when=concurrent.futures.ALL_COMPLETED)
            except KeyboardInterrupt:
                logger.info("Gracefully shutting down...")
                self.running = False
                for future in futures:
                    future.cancel()
        
        duration = time.time() - start_time
        logger.info(f"Verification completed in {duration:.1f} seconds")

def main():
    """Main execution function"""
    try:
        config = Config()
        base_path = Path("data")
        sites_path = base_path / "sites.txt"
        credentials_path = base_path / "credentials.txt"
        results_path = base_path / "results"
        
        # Create directories if they don't exist
        results_path.mkdir(parents=True, exist_ok=True)
        
        # Load data
        site_loader = SiteLoader()
        credentials_loader = CredentialsLoader()
        
        sites = site_loader.load(sites_path)
        credentials = credentials_loader.load(credentials_path)
        
        if not sites or not credentials:
            logger.error("No sites or credentials loaded. Exiting.")
            return
        
        # Start login process
        login_manager = LoginManager(config)
        login_manager.process_sites(sites, credentials)
        
    except Exception as e:
        logger.error(f"Application error: {str(e)}")
        raise

if __name__ == "__main__":
    main()