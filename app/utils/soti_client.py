import requests
from flask import current_app
import json
from datetime import datetime, timedelta
import base64
import time
from bs4 import BeautifulSoup

class SotiClient:
    """SOTI MobiControl API Client"""
    
    def __init__(self, server_url, client_id=None, client_secret=None, username=None, password=None):
        """Initialize SOTI client with credentials"""
        self.server_url = self._clean_server_url(server_url)
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.token = None
        self.token_expiry = None
        self.session = self._create_session()
        
    def _clean_server_url(self, url):
        """Clean and standardize the server URL"""
        # Remove any trailing slashes and whitespace
        url = url.strip().rstrip('/')
        
        # If it's a full token URL, extract the domain
        if '/MobiControl/api/token' in url:
            url = url.split('/MobiControl')[0]
        elif '/MobiControl/api/oauth/token' in url:
            url = url.split('/MobiControl')[0]
        elif '/MobiControl' in url:
            url = url.split('/MobiControl')[0]
        
        # Remove protocol if present
        if url.startswith('https://'):
            url = url[8:]
        elif url.startswith('http://'):
            url = url[7:]
        
        # Remove any remaining paths
        url = url.split('/')[0]
        
        # Ensure proper domain format
        if not url.endswith('.mobicontrol.cloud'):
            # If it's a tenant ID only, append domain
            if '.' not in url:
                url = f"{url}.mobicontrol.cloud"
            # Convert soti.net to mobicontrol.cloud
            elif '.soti.net' in url:
                url = url.replace('.soti.net', '.mobicontrol.cloud')
        
        return f"https://{url}"
        
    def _create_session(self):
        """Create a requests session with retry logic"""
        session = requests.Session()
        session.verify = True  # Enable SSL verification
        return session
        
    def _parse_error_message(self, response):
        """Parse error message from response"""
        try:
            if response.headers.get('Content-Type', '').startswith('application/json'):
                data = response.json()
                if isinstance(data, dict):
                    if 'error' in data:
                        return data['error']
                    elif 'message' in data:
                        return data['message']
                    elif 'error_description' in data:
                        return data['error_description']
                elif isinstance(data, str):
                    return data
            return f"HTTP {response.status_code}: {response.text or 'No error message provided'}"
        except Exception as e:
            current_app.logger.error(f"Error parsing error message: {str(e)}")
            return f"HTTP {response.status_code}"

    def authenticate(self):
        """Authenticate with SOTI MobiControl API using password grant"""
        try:
            # Validate required credentials
            if not all([self.client_id, self.client_secret, self.username, self.password]):
                current_app.logger.error("Missing required credentials")
                missing = []
                if not self.client_id: missing.append('client_id')
                if not self.client_secret: missing.append('client_secret')
                if not self.username: missing.append('username')
                if not self.password: missing.append('password')
                current_app.logger.error(f"Missing credentials: {', '.join(missing)}")
                return False

            # Construct OAuth token endpoint URL
            token_url = f"{self.server_url}/MobiControl/api/token"
            current_app.logger.info(f"Authenticating with SOTI OAuth endpoint: {token_url}")
            
            # Create Basic auth header using client credentials
            # Format: Basic base64(ClientID:ClientSecret)
            auth_string = f"{self.client_id}:{self.client_secret}"
            auth_bytes = auth_string.encode('utf-8')
            basic_auth = base64.b64encode(auth_bytes).decode('utf-8')
            
            # Prepare headers with Basic auth and proper content type
            headers = {
                'Authorization': f'Basic {basic_auth}',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
                'Host': self.server_url.replace('https://', '')
            }
            
            # Prepare form data for password grant
            # Format: grant_type=password&username=Administrator&password=1
            data = {
                'grant_type': 'password',
                'username': self.username,
                'password': self.password
            }
            
            current_app.logger.debug(f"Request headers: {headers}")
            current_app.logger.debug(f"Request data: {data}")
            current_app.logger.debug(f"Request URL: {token_url}")
            current_app.logger.debug(f"Request body: {data}")
            
            try:
                response = self.session.post(
                    token_url,
                    headers=headers,
                    data=data,
                    verify=True,
                    timeout=30
                )
                
                current_app.logger.debug(f"Token response status: {response.status_code}")
                current_app.logger.debug(f"Token response headers: {dict(response.headers)}")
                
                # Handle specific HTTP status codes based on SOTI API documentation
                if response.status_code == 200:
                    try:
                        token_data = response.json()
                        self.token = token_data.get('access_token')
                        self.token_type = token_data.get('token_type')
                        
                        # Verify token type is 'bearer' as per documentation
                        if self.token_type and self.token_type.lower() != 'bearer':
                            current_app.logger.error(f"Unexpected token type: {self.token_type}")
                            return False
                        
                        if self.token:
                            # Calculate token expiry from expires_in (in seconds)
                            expires_in = token_data.get('expires_in', 3600)  # Default 1 hour
                            self.token_expiry = datetime.now() + timedelta(seconds=expires_in)
                            
                            current_app.logger.info("SOTI OAuth authentication successful")
                            current_app.logger.debug(f"Token received, expires in {expires_in} seconds")
                            return True
                        else:
                            current_app.logger.error("No access token in response")
                            current_app.logger.debug(f"Response data: {token_data}")
                            return False
                            
                    except json.JSONDecodeError as je:
                        current_app.logger.error(f"Failed to parse token response: {str(je)}")
                        current_app.logger.debug(f"Response content: {response.text[:500]}")
                        return False
                        
                elif response.status_code == 400:
                    # Contract validation error
                    error_data = response.json() if response.headers.get('Content-Type', '').startswith('application/json') else {}
                    error_code = error_data.get('ErrorCode')
                    error_msg = error_data.get('ErrorMessage', 'Invalid request')
                    help_link = error_data.get('HelpLink', '')
                    
                    error_details = f"Error {error_code}: {error_msg}"
                    if help_link:
                        error_details += f" (Help: {help_link})"
                        
                    current_app.logger.error(f"Authentication failed - Bad Request: {error_details}")
                    return False
                    
                elif response.status_code in [401, 403]:
                    # Security error - login failed or unauthorized
                    error_data = response.json() if response.headers.get('Content-Type', '').startswith('application/json') else {}
                    error_msg = error_data.get('ErrorMessage', 'Authentication failed')
                    current_app.logger.error(f"Authentication failed: {error_msg}")
                    return False
                    
                elif response.status_code == 422:
                    # Business logic error
                    error_data = response.json() if response.headers.get('Content-Type', '').startswith('application/json') else {}
                    error_code = error_data.get('ErrorCode')
                    error_msg = error_data.get('ErrorMessage', 'Business logic error')
                    help_link = error_data.get('HelpLink', '')
                    
                    error_details = f"Error {error_code}: {error_msg}"
                    if help_link:
                        error_details += f" (Help: {help_link})"
                        
                    current_app.logger.error(f"Authentication failed - Business Logic Error: {error_details}")
                    return False
                    
                elif response.status_code == 500:
                    # Server error
                    error_data = response.json() if response.headers.get('Content-Type', '').startswith('application/json') else {}
                    error_msg = error_data.get('ErrorMessage', 'Internal Server Error')
                    current_app.logger.error(f"Authentication failed - Server Error: {error_msg}")
                    current_app.logger.error("Please check Management Service logs and contact SOTI Support")
                    return False
                    
                else:
                    error_msg = self._parse_error_message(response)
                    current_app.logger.error(f"Authentication failed with status {response.status_code}: {error_msg}")
                    current_app.logger.debug(f"Full response: {response.text[:500]}")
                    return False
                    
            except requests.exceptions.SSLError:
                current_app.logger.error("SSL verification failed. Check server certificate.")
                return False
                
            except requests.exceptions.ConnectionError:
                current_app.logger.error(f"Connection failed to {token_url}. Check server URL and network connection.")
                return False
                
            except requests.exceptions.Timeout:
                current_app.logger.error("Authentication request timed out")
                return False
                
            except requests.exceptions.RequestException as e:
                current_app.logger.error(f"Request failed: {str(e)}")
                return False
                
        except Exception as e:
            current_app.logger.error(f"Error during OAuth authentication: {str(e)}")
            current_app.logger.debug("Exception details:", exc_info=True)
            return False

    def refresh_auth_token(self):
        """Refresh the access token using refresh token"""
        try:
            if not self.refresh_token:
                current_app.logger.error("No refresh token available")
                return False

            # Construct token endpoint URL
            token_url = f"{self.server_url}/MobiControl/api/token"
            
            # Create Basic auth header using client credentials
            auth_string = f"{self.client_id}:{self.client_secret}"
            auth_bytes = auth_string.encode('utf-8')
            basic_auth = base64.b64encode(auth_bytes).decode('utf-8')
            
            # Prepare headers with Basic auth
            headers = {
                'Authorization': f'Basic {basic_auth}',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            # Prepare form data for refresh token grant
            data = {
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token
            }
            
            response = self.session.post(
                token_url,
                headers=headers,
                data=data,
                verify=True,
                timeout=30
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.token = token_data.get('access_token')
                self.refresh_token = token_data.get('refresh_token', self.refresh_token)
                expires_in = token_data.get('expires_in', 3600)
                self.token_expiry = datetime.now() + timedelta(seconds=expires_in)
                self.token_type = token_data.get('token_type', 'Bearer')
                return True
            else:
                error_msg = self._parse_error_message(response)
                current_app.logger.error(f"Token refresh failed: {error_msg}")
                return False

        except Exception as e:
            current_app.logger.error(f"Error refreshing token: {str(e)}")
            return False

    def ensure_authenticated(self):
        """Ensure we have a valid OAuth token"""
        if not self.token:
            return self.authenticate()
            
        # Check if token is expired or about to expire (within 5 minutes)
        if self.token_expiry and datetime.now() >= (self.token_expiry - timedelta(minutes=5)):
            return self.authenticate()
            
        return True

    def get_devices(self):
        """Get list of all devices"""
        try:
            if not self.ensure_authenticated():
                raise Exception("Failed to authenticate with SOTI")
            
            devices_url = f"{self.server_url}/MobiControl/api/devices"
            
            current_app.logger.debug(f"Fetching devices from SOTI: {devices_url}")
            
            headers = {
                'Authorization': f'{self.token_type} {self.token}',
                'Accept': 'application/json'
            }
            
            response = self.session.get(devices_url, headers=headers, timeout=30)
            
            current_app.logger.debug(f"Response status: {response.status_code}")
            current_app.logger.debug(f"Response headers: {dict(response.headers)}")
            
            if response.status_code == 200:
                devices_data = response.json()
                
                # Process devices and calculate stats
                devices = []
                stats = {'online': 0, 'offline': 0, 'pending': 0, 'total': 0}
                
                for device in devices_data:
                    device_info = {
                        'id': device.get('id', ''),
                        'name': device.get('deviceName', ''),
                        'friendlyName': device.get('deviceFriendlyName', ''),
                        'status': 'Online' if device.get('isOnline', False) else 'Offline',
                        'platform': device.get('platformType', ''),
                        'model': device.get('model', ''),
                        'osVersion': device.get('osVersion', ''),
                        'lastConnected': device.get('lastConnectedTime', ''),
                        'serialNumber': device.get('serialNumber', ''),
                        'imei': device.get('imei', ''),
                        'phoneNumber': device.get('phoneNumber', ''),
                        'wifiMacAddress': device.get('wifiMacAddress', '')
                    }
                    
                    devices.append(device_info)
                    
                    # Update stats
                    if device.get('isOnline', False):
                        stats['online'] += 1
                    else:
                        stats['offline'] += 1
                    
                    if device.get('enrollmentStatus', '').lower() == 'pending':
                        stats['pending'] += 1
                
                stats['total'] = len(devices)
                
                return {
                    'devices': devices,
                    'stats': stats
                }
            else:
                error_msg = self._parse_error_message(response)
                current_app.logger.error(f"Failed to get devices: {response.status_code} - {error_msg}")
                current_app.logger.debug(f"Response headers: {dict(response.headers)}")
                current_app.logger.debug(f"Response content: {response.text[:1000]}")
                raise Exception(f"Failed to get devices: {error_msg}")
                
        except Exception as e:
            current_app.logger.error(f"Error getting devices: {str(e)}")
            raise

    def get_device_details(self, device_id):
        """Get detailed information for a specific device"""
        try:
            if not self.ensure_authenticated():
                raise Exception("Failed to authenticate with SOTI")
            
            device_url = f"{self.server_url}/MobiControl/api/devices/{device_id}"
            
            headers = {
                'Authorization': f'{self.token_type} {self.token}',
                'Accept': 'application/json'
            }
            
            current_app.logger.debug(f"Fetching device details from SOTI: {device_url}")
            current_app.logger.debug(f"Request headers: {headers}")
            
            response = self.session.get(device_url, headers=headers, timeout=30)
            
            current_app.logger.debug(f"Response status: {response.status_code}")
            current_app.logger.debug(f"Response headers: {dict(response.headers)}")
            
            if response.status_code == 200:
                device = response.json()
                device_info = {
                    'id': device.get('id', ''),
                    'name': device.get('deviceName', ''),
                    'friendlyName': device.get('deviceFriendlyName', ''),
                    'status': 'Online' if device.get('isOnline', False) else 'Offline',
                    'platform': device.get('platformType', ''),
                    'model': device.get('model', ''),
                    'osVersion': device.get('osVersion', ''),
                    'lastConnected': device.get('lastConnectedTime', ''),
                    'serialNumber': device.get('serialNumber', ''),
                    'imei': device.get('imei', ''),
                    'phoneNumber': device.get('phoneNumber', ''),
                    'wifiMacAddress': device.get('wifiMacAddress', ''),
                    'enrollmentStatus': device.get('enrollmentStatus', ''),
                    'complianceStatus': device.get('complianceStatus', ''),
                    'lastReported': device.get('lastReportedTime', ''),
                    'manufacturer': device.get('manufacturer', ''),
                    'ownership': device.get('ownership', ''),
                    'location': {
                        'latitude': device.get('latitude'),
                        'longitude': device.get('longitude'),
                        'lastUpdated': device.get('locationLastUpdatedTime')
                    }
                }
                return device_info
            else:
                error_msg = self._parse_error_message(response)
                current_app.logger.error(f"Failed to get device details: {response.status_code} - {error_msg}")
                raise Exception(f"Failed to get device details: {error_msg}")
                
        except Exception as e:
            current_app.logger.error(f"Error getting device details: {str(e)}")
            raise

    def refresh_device(self, device_id):
        """Request device information refresh"""
        try:
            if not self.ensure_authenticated():
                raise Exception("Failed to authenticate with SOTI")
            
            refresh_url = f"{self.server_url}/MobiControl/api/devices/{device_id}/refresh"
            
            headers = {
                'Authorization': f'{self.token_type} {self.token}',
                'Accept': 'application/json'
            }
            
            current_app.logger.debug(f"Requesting device refresh from SOTI: {refresh_url}")
            current_app.logger.debug(f"Request headers: {headers}")
            
            response = self.session.post(refresh_url, headers=headers, timeout=30)
            
            current_app.logger.debug(f"Response status: {response.status_code}")
            current_app.logger.debug(f"Response headers: {dict(response.headers)}")
            
            if response.status_code in [200, 202]:
                return True
            else:
                error_msg = self._parse_error_message(response)
                current_app.logger.error(f"Failed to refresh device: {response.status_code} - {error_msg}")
                raise Exception(f"Failed to refresh device: {error_msg}")
                
        except Exception as e:
            current_app.logger.error(f"Error refreshing device: {str(e)}")
            raise 