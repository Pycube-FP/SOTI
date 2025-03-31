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
        """Create a session with browser-like headers"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Cache-Control': 'max-age=0'
        })
        return session

    def _handle_waf_challenge(self, response):
        """Handle WAF challenge by following response content"""
        if response.status_code == 202 and 'x-amzn-waf-action' in response.headers:
            try:
                # Get the response content which may contain JavaScript challenge
                content = response.text
                if content:
                    current_app.logger.debug("Received WAF challenge content")
                    
                    # Make additional request to the same URL to complete the challenge
                    challenge_response = self.session.get(
                        response.url,
                        headers={
                            **self.session.headers,
                            'Referer': str(response.url),
                            'Origin': self.server_url
                        },
                        allow_redirects=True
                    )
                    
                    # Log challenge response details
                    current_app.logger.debug(f"Challenge response status: {challenge_response.status_code}")
                    current_app.logger.debug(f"Challenge response headers: {dict(challenge_response.headers)}")
                    
                    # Return True if challenge seems to be completed
                    return challenge_response.status_code in [200, 302]
                    
            except Exception as e:
                current_app.logger.error(f"Error handling WAF challenge: {str(e)}")
        return False

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
                elif isinstance(data, str):
                    return data
            return f"HTTP {response.status_code}: {response.text or 'No error message provided'}"
        except Exception as e:
            current_app.logger.error(f"Error parsing error message: {str(e)}")
            return f"HTTP {response.status_code}"

    def _get_basic_auth_header(self):
        """Generate Basic Auth header value for client credentials"""
        if not self.username or not self.password:
            raise ValueError("Username and Password are required")
            
        auth_string = f"{self.username}:{self.password}"
        auth_bytes = auth_string.encode('utf-8')
        return base64.b64encode(auth_bytes).decode('utf-8')

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
            
            # Create Basic auth header as per documentation
            auth_string = f"{self.client_id}:{self.client_secret}"
            auth_bytes = auth_string.encode('utf-8')
            basic_auth = base64.b64encode(auth_bytes).decode('utf-8')
            
            # Prepare headers with Basic auth
            headers = {
                'Authorization': f'Basic {basic_auth}',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            # Prepare form data for password grant
            data = {
                'grant_type': 'password',
                'username': self.username,
                'password': self.password
            }
            
            current_app.logger.debug(f"Request headers: {headers}")
            current_app.logger.debug(f"Request data: {data}")
            
            response = self.session.post(
                token_url,
                headers=headers,
                data=data,
                verify=True
            )
            
            current_app.logger.debug(f"Token response status: {response.status_code}")
            current_app.logger.debug(f"Token response headers: {dict(response.headers)}")
            
            if response.status_code == 200:
                try:
                    token_data = response.json()
                    self.token = token_data.get('access_token')
                    
                    if self.token:
                        expires_in = token_data.get('expires_in', 3600)
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
            else:
                error_msg = self._parse_error_message(response)
                current_app.logger.error(f"Authentication failed: {error_msg}")
                current_app.logger.debug(f"Full response: Status={response.status_code}, Content={response.text[:500]}")
                return False
                
        except Exception as e:
            current_app.logger.error(f"Error during OAuth authentication: {str(e)}")
            current_app.logger.debug("Exception details:", exc_info=True)
            return False

    def ensure_authenticated(self):
        """Ensure we have a valid OAuth token"""
        if not self.token or (self.token_expiry and datetime.now() >= self.token_expiry):
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
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            response = self.session.get(devices_url, headers=headers)
            
            current_app.logger.debug(f"Response status: {response.status_code}")
            current_app.logger.debug(f"Response headers: {dict(response.headers)}")
            
            if response.status_code == 200:
                devices_data = response.json()
                current_app.logger.debug(f"Raw devices data: {json.dumps(devices_data)[:1000]}")
                
                # Transform SOTI device data to our format
                devices = []
                # Handle array response
                device_list = devices_data if isinstance(devices_data, list) else [devices_data]
                
                for device in device_list:
                    # Check connection state first
                    connection_state = str(device.get('ConnectionState', '')).lower()
                    device_status = str(device.get('DeviceStatus', '')).lower()
                    is_online = str(device.get('IsOnline', '')).lower()
                    
                    # Log raw status values for debugging
                    current_app.logger.debug(f"Raw status values - ConnectionState: {connection_state}, DeviceStatus: {device_status}, IsOnline: {is_online}")
                    
                    # Determine online status
                    status = 'Online' if (
                        connection_state in ['online', 'true', '1'] or
                        device_status in ['online', 'true', '1'] or
                        is_online in ['online', 'true', '1', 'yes']
                    ) else 'Offline'
                    
                    # Extract device info with proper field mapping
                    device_info = {
                        'id': (
                            device.get('Id') or 
                            device.get('id') or 
                            device.get('DeviceId') or 
                            device.get('deviceId') or 
                            ''
                        ),
                        'name': (
                            device.get('DeviceName') or 
                            device.get('Name') or 
                            device.get('deviceName') or 
                            device.get('name') or 
                            device.get('FriendlyName') or
                            device.get('friendlyName') or
                            'Unnamed Device'
                        ),
                        'status': status,
                        'model': (
                            device.get('Model') or 
                            device.get('DeviceModel') or 
                            device.get('model') or 
                            device.get('deviceModel') or
                            device.get('HardwareModel') or
                            device.get('hardwareModel') or
                            'N/A'
                        ),
                        'osVersion': (
                            device.get('OsVersion') or 
                            device.get('OSVersion') or
                            device.get('OperatingSystem') or 
                            device.get('osVersion') or 
                            device.get('operatingSystem') or
                            device.get('OSName') or
                            device.get('osName') or
                            'N/A'
                        ),
                        'serialNumber': (
                            device.get('SerialNumber') or
                            device.get('serialNumber') or
                            device.get('Serial') or
                            device.get('serial') or
                            'N/A'
                        ),
                        'manufacturer': (
                            device.get('Manufacturer') or
                            device.get('manufacturer') or
                            device.get('DeviceManufacturer') or
                            device.get('deviceManufacturer') or
                            'N/A'
                        ),
                        'lastSeen': (
                            device.get('LastSeen') or
                            device.get('LastSeenTime') or
                            device.get('lastSeen') or
                            device.get('lastSeenTime') or
                            'N/A'
                        ),
                        'lastConnected': (
                            device.get('LastConnected') or
                            device.get('LastConnectedTime') or
                            device.get('lastConnected') or
                            device.get('lastConnectedTime') or
                            'N/A'
                        ),
                        'batteryLevel': (
                            device.get('BatteryLevel') or
                            device.get('batteryLevel') or
                            device.get('Battery') or
                            device.get('battery') or
                            'N/A'
                        ),
                        'ipAddress': (
                            device.get('IPAddress') or
                            device.get('ipAddress') or
                            device.get('IP') or
                            device.get('ip') or
                            'N/A'
                        ),
                        'wifiSSID': (
                            device.get('WifiSSID') or
                            device.get('wifiSSID') or
                            device.get('SSID') or
                            device.get('ssid') or
                            'N/A'
                        ),
                        'location': {
                            'latitude': device.get('Latitude') or device.get('latitude') or 'N/A',
                            'longitude': device.get('Longitude') or device.get('longitude') or 'N/A',
                            'address': device.get('Address') or device.get('address') or 'N/A'
                        }
                    }
                    
                    # Log the mapping for debugging
                    current_app.logger.debug(f"Device status determination - Final status: {status}")
                    current_app.logger.debug(f"Mapped device data: {json.dumps(device_info)}")
                    devices.append(device_info)
                
                # Calculate statistics
                total_devices = len(devices)
                online_devices = sum(1 for d in devices if d['status'] == 'Online')
                offline_devices = total_devices - online_devices
                
                stats = {
                    'total': total_devices,
                    'online': online_devices,
                    'offline': offline_devices,
                    'pending': 0  # This can be updated based on your requirements
                }
                
                current_app.logger.debug(f"Device statistics: Online={online_devices}, Offline={offline_devices}, Total={total_devices}")
                
                return {'devices': devices, 'stats': stats}
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
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            current_app.logger.debug(f"Fetching device details from SOTI: {device_url}")
            current_app.logger.debug(f"Request headers: {headers}")
            
            response = self.session.get(device_url, headers=headers)
            
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
                    'wifiMacAddress': device.get('wifiMacAddress', '')
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
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            current_app.logger.debug(f"Requesting device refresh from SOTI: {refresh_url}")
            current_app.logger.debug(f"Request headers: {headers}")
            
            response = self.session.post(refresh_url, headers=headers)
            
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