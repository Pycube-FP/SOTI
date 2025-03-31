from typing import Dict, List, Optional
import requests
from datetime import datetime, timedelta
from flask import current_app
from app.utils.cache import cache

class SotiService:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self.base_url = None
        self.client_id = None
        self.client_secret = None
        self.username = None
        self.password = None
        self.token = None
        self.headers = None

    def _ensure_initialized(self):
        """Ensure the service is initialized with current application context"""
        if not self.base_url:
            current_app.logger.info("Initializing SOTI service...")
            self.base_url = current_app.config.get('SOTI_SERVER_URL')
            self.client_id = current_app.config.get('SOTI_CLIENT_ID')
            self.client_secret = current_app.config.get('SOTI_CLIENT_SECRET')
            self.username = current_app.config.get('SOTI_USERNAME')
            self.password = current_app.config.get('SOTI_PASSWORD')
            
            # Log configuration status (without sensitive data)
            config_status = {
                'base_url': bool(self.base_url),
                'client_id': bool(self.client_id),
                'client_secret': bool(self.client_secret),
                'username': bool(self.username),
                'password': bool(self.password)
            }
            current_app.logger.info(f"SOTI configuration status: {config_status}")
            
            if not all([self.base_url, self.client_id, self.client_secret, self.username, self.password]):
                missing = [k for k, v in config_status.items() if not v]
                error_msg = f"SOTI configuration is incomplete. Missing: {', '.join(missing)}"
                current_app.logger.error(error_msg)
                raise Exception(error_msg)
            
            # Authenticate and get token
            try:
                self.token = self._authenticate()
                self.headers = {
                    'Authorization': f'Bearer {self.token}',
                    'Content-Type': 'application/json'
                }
                current_app.logger.info("SOTI service initialized successfully")
            except Exception as e:
                current_app.logger.error(f"SOTI authentication failed: {str(e)}")
                raise

    def _authenticate(self) -> str:
        """
        Authenticate with SOTI API and get access token.
        """
        try:
            current_app.logger.info(f"Authenticating with SOTI server at {self.base_url}")
            # Use the full token URL directly
            auth_url = "https://a009866.mobicontrol.cloud/MobiControl/api/token"
            
            auth_data = {
                'grant_type': 'password',
                'username': self.username,
                'password': self.password,
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
            
            current_app.logger.debug(f"Attempting authentication to {auth_url}")
            current_app.logger.debug(f"Using client_id: {self.client_id}")
            
            # Log request details for debugging
            current_app.logger.debug(f"Auth request data: {auth_data}")
            
            auth_response = requests.post(
                auth_url,
                data=auth_data,  # Using form data
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                },
                verify=True
            )
            
            current_app.logger.debug(f"Auth response status: {auth_response.status_code}")
            current_app.logger.debug(f"Auth response headers: {dict(auth_response.headers)}")
            current_app.logger.debug(f"Auth response content: {auth_response.text}")
            
            if not auth_response.ok:
                error_msg = f"Authentication failed with status {auth_response.status_code}"
                try:
                    error_details = auth_response.json()
                    error_msg += f": {error_details}"
                except:
                    error_msg += f": {auth_response.text}"
                current_app.logger.error(error_msg)
                current_app.logger.error(f"Request URL: {auth_url}")
                current_app.logger.error(f"Request headers: {auth_response.request.headers}")
                raise Exception("Failed to authenticate with SOTI. Please check your credentials and try again.")
            
            try:
                token_data = auth_response.json()
                current_app.logger.debug(f"Token response data: {token_data}")
                
                if 'access_token' not in token_data:
                    error_msg = f"Invalid token response: {token_data}"
                    current_app.logger.error(error_msg)
                    raise Exception("Invalid authentication response from SOTI server")
                    
                current_app.logger.info("SOTI authentication successful")
                return token_data['access_token']
            except ValueError as e:
                error_msg = f"Failed to parse authentication response: {str(e)}"
                current_app.logger.error(error_msg)
                current_app.logger.error(f"Response content: {auth_response.text}")
                raise Exception("Invalid response from SOTI authentication server")
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to authenticate with SOTI: {str(e)}"
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_details = e.response.json()
                    error_msg += f" - Response: {error_details}"
                except:
                    error_msg += f" - Response: {e.response.text}"
            current_app.logger.error(error_msg)
            current_app.logger.error(f"Full exception details: {str(e)}")
            raise Exception("Failed to authenticate with SOTI. Please check your credentials and try again.")

    @cache.memoize(timeout=300)  # Cache for 5 minutes
    def get_devices(self) -> Dict:
        """
        Get all devices and their status.
        Returns a dictionary containing devices list and stats.
        """
        self._ensure_initialized()
        try:
            current_app.logger.info("Fetching devices from SOTI...")
            
            # Construct the devices endpoint URL using the base URL without /token
            base_url = "https://a009866.mobicontrol.cloud/MobiControl/api"
            devices_url = f"{base_url}/devices"
            
            # Prepare headers with token
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            # Parameters for pagination
            params = {
                'skip': 0,
                'take': 100  # Increased to get more devices per page
            }
            
            current_app.logger.debug(f"Making request to: {devices_url}")
            current_app.logger.debug(f"Using headers: {headers}")
            current_app.logger.debug(f"Using params: {params}")
            
            # Make the request with proper error handling
            response = requests.get(
                devices_url,
                headers=headers,
                params=params,
                verify=True,
                timeout=30
            )
            
            current_app.logger.debug(f"Devices response status: {response.status_code}")
            current_app.logger.debug(f"Devices response headers: {dict(response.headers)}")
            
            if not response.ok:
                error_msg = f"Failed to fetch devices with status {response.status_code}"
                try:
                    error_details = response.json()
                    error_msg += f": {error_details}"
                except:
                    error_msg += f": {response.text}"
                current_app.logger.error(error_msg)
                raise Exception("Failed to fetch devices from SOTI. Please check the application logs.")
            
            try:
                devices_data = response.json()
                current_app.logger.debug(f"Raw API response: {devices_data}")
                
                # Transform the data to match the expected format
                devices = []
                if isinstance(devices_data, list):
                    device_list = devices_data
                elif isinstance(devices_data, dict):
                    if 'Devices' in devices_data:
                        device_list = devices_data['Devices']
                    elif 'devices' in devices_data:
                        device_list = devices_data['devices']
                    else:
                        device_list = [devices_data]  # Single device response
                else:
                    device_list = []
                
                for device in device_list:
                    # Debug log to see raw device data and available fields
                    current_app.logger.debug(f"Raw device data keys: {device.keys()}")
                    current_app.logger.debug(f"Looking for serial number in fields: {[
                        ('HardwareSerialNumber', device.get('HardwareSerialNumber')),
                        ('MobileSerialNumber', device.get('MobileSerialNumber')),
                        ('SerialNumber', device.get('SerialNumber')),
                        ('serialNumber', device.get('serialNumber')),
                        ('Serial', device.get('Serial')),
                        ('DeviceSerial', device.get('DeviceSerial')),
                        ('deviceSerial', device.get('deviceSerial')),
                        ('HardwareId', device.get('HardwareId')),
                        ('hardwareId', device.get('hardwareId')),
                        ('IMEI_MEID_ESN', device.get('IMEI_MEID_ESN'))
                    ]}")
                    
                    # Use IsAgentOnline for status
                    is_online = device.get('IsAgentOnline', False)
                    status = 'Online' if is_online else 'Offline'
                    
                    # Extract OS Version with multiple possible field names
                    os_version = (
                        device.get('OSVersion') or 
                        device.get('OsVersion') or 
                        device.get('OperatingSystem') or 
                        device.get('OS') or 
                        'Unknown OS'
                    )
                    
                    # Extract Serial Number with multiple possible field names
                    serial_number = None
                    serial_field_names = [
                        'ManufacturerSerialNumber',  # Add this as first priority
                        'HardwareSerialNumber',
                        'MobileSerialNumber',
                        'SerialNumber',
                        'serialNumber',
                        'Serial',
                        'DeviceSerial',
                        'deviceSerial',
                        'HardwareId',
                        'hardwareId',
                        'IMEI_MEID_ESN'
                    ]
                    
                    for field in serial_field_names:
                        if device.get(field):
                            serial_number = device.get(field)
                            current_app.logger.debug(f"Found serial number in field '{field}': {serial_number}")
                            break
                    
                    if not serial_number and device.get('DeviceKind') == 'macOS':
                        # Special handling for Mac devices - check additional fields
                        serial_number = (
                            device.get('ManufacturerSerialNumber') or  # Try manufacturer serial first
                            device.get('HardwareSerialNumber') or      # Then hardware serial
                            device.get('SystemSerialNumber') or        # Then system serial
                            'Unknown SN'                               # Fallback
                        )
                        current_app.logger.debug(f"Mac device serial number found: {serial_number}")
                    
                    if not serial_number:
                        current_app.logger.debug("No serial number found in any expected fields")
                        serial_number = 'Unknown SN'
                    
                    transformed_device = {
                        'id': device.get('DeviceId') or device.get('Id') or '',
                        'name': device.get('DeviceName') or device.get('Name') or 'Unknown Device',
                        'status': status,
                        'model': device.get('Model') or device.get('DeviceModel') or 'Unknown Model',
                        'manufacturer': device.get('Manufacturer') or 'Unknown Manufacturer',
                        'osVersion': os_version,
                        'SerialNumber': serial_number,
                        'lastSeen': device.get('LastSeen') or device.get('LastSeenTime'),
                        'lastUpdated': device.get('LastUpdated') or device.get('LastUpdateTime')
                    }
                    
                    # Debug log to see transformed device data
                    current_app.logger.debug(f"Transformed device data: {transformed_device}")
                    
                    devices.append(transformed_device)
                
                current_app.logger.debug(f"Transformed devices data: {devices}")
                
                # Calculate statistics
                stats = self._calculate_device_stats(devices)
                current_app.logger.info(f"Successfully fetched {len(devices)} devices")
                
                return {
                    'devices': devices,
                    'stats': stats
                }
            except ValueError as e:
                error_msg = f"Invalid JSON response from SOTI API: {str(e)}"
                current_app.logger.error(error_msg)
                current_app.logger.error(f"Response content: {response.text}")
                raise Exception("Failed to parse device data from SOTI")
                
        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to fetch devices: {str(e)}"
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_details = e.response.json()
                    error_msg += f" - Response: {error_details}"
                except:
                    error_msg += f" - Response: {e.response.text}"
            current_app.logger.error(error_msg)
            current_app.logger.error(f"Full exception details: {str(e)}")
            raise Exception("Failed to fetch devices from SOTI. Please check the application logs.")

    def refresh_devices(self) -> Dict:
        """
        Refresh all devices and return updated data.
        Invalidates the cache and fetches fresh data.
        """
        self._ensure_initialized()
        try:
            # Invalidate the cache
            cache.delete_memoized(self.get_devices)
            
            # For SOTI API, we'll just fetch fresh data since there's no bulk refresh endpoint
            current_app.logger.info("Refreshing devices by fetching fresh data...")
            return self.get_devices()
            
        except Exception as e:
            error_msg = f"Failed to refresh devices: {str(e)}"
            current_app.logger.error(error_msg)
            raise Exception("Failed to refresh devices. Please check the application logs.")

    def refresh_device(self, device_id: str) -> Dict:
        """
        Refresh a specific device and return updated data.
        """
        self._ensure_initialized()
        try:
            # Prepare headers
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Use the correct base URL and endpoint
            base_url = "https://a009866.mobicontrol.cloud/MobiControl/api"
            device_url = f"{base_url}/devices/{device_id}"
            
            current_app.logger.debug(f"Refreshing device {device_id} by fetching from: {device_url}")
            current_app.logger.debug(f"Using headers: {headers}")
            
            # Get the latest device data
            response = requests.get(
                device_url,
                headers=headers,
                verify=True,
                timeout=30
            )
            
            current_app.logger.debug(f"Device refresh response status: {response.status_code}")
            current_app.logger.debug(f"Device refresh response headers: {dict(response.headers)}")
            
            if not response.ok:
                error_msg = f"Failed to refresh device {device_id} with status {response.status_code}"
                try:
                    error_details = response.json()
                    error_msg += f": {error_details}"
                except:
                    error_msg += f": {response.text}"
                current_app.logger.error(error_msg)
                raise Exception(f"Failed to refresh device {device_id}. Please check the application logs.")
            
            # Invalidate the cache
            cache.delete_memoized(self.get_devices)
            cache.delete_memoized(self.get_device_details, device_id)
            
            # Get updated device list
            return self.get_devices()
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to refresh device {device_id}: {str(e)}"
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_details = e.response.json()
                    error_msg += f" - Response: {error_details}"
                except:
                    error_msg += f" - Response: {e.response.text}"
            current_app.logger.error(error_msg)
            raise Exception(f"Failed to refresh device {device_id}. Please check the application logs.")

    @cache.memoize(timeout=300)  # Cache for 5 minutes
    def get_device_details(self, device_id: str) -> Optional[Dict]:
        """
        Get detailed information for a specific device.
        """
        self._ensure_initialized()
        try:
            # Construct the device details URL
            base_url = "https://a009866.mobicontrol.cloud/MobiControl/api"
            device_url = f"{base_url}/devices/{device_id}"
            
            # Prepare headers
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            current_app.logger.debug(f"Fetching device details from: {device_url}")
            current_app.logger.debug(f"Using headers: {headers}")
            
            response = requests.get(
                device_url,
                headers=headers,
                verify=True,
                timeout=30
            )
            
            current_app.logger.debug(f"Device details response status: {response.status_code}")
            current_app.logger.debug(f"Device details response headers: {dict(response.headers)}")
            
            if not response.ok:
                error_msg = f"Failed to fetch device details with status {response.status_code}"
                try:
                    error_details = response.json()
                    error_msg += f": {error_details}"
                except:
                    error_msg += f": {response.text}"
                current_app.logger.error(error_msg)
                raise Exception(f"Failed to fetch details for device {device_id}")
            
            try:
                device_data = response.json()
                current_app.logger.debug(f"Device details raw response: {device_data}")
                return device_data
            except ValueError as e:
                error_msg = f"Invalid JSON response from SOTI API: {str(e)}"
                current_app.logger.error(error_msg)
                current_app.logger.error(f"Response content: {response.text}")
                raise Exception(f"Failed to parse details for device {device_id}")
                
        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to fetch device details: {str(e)}"
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_details = e.response.json()
                    error_msg += f" - Response: {error_details}"
                except:
                    error_msg += f" - Response: {e.response.text}"
            current_app.logger.error(error_msg)
            current_app.logger.error(f"Full exception details: {str(e)}")
            raise Exception(f"Failed to fetch details for device {device_id}")

    def _calculate_device_stats(self, devices: List[Dict]) -> Dict:
        """
        Calculate device statistics from the device list.
        """
        stats = {
            'total': len(devices),
            'online': 0,
            'offline': 0,
            'pending': 0
        }

        for device in devices:
            if device['status'] == 'Online':
                stats['online'] += 1
            elif device['status'] == 'Offline':
                stats['offline'] += 1
            
            # Check if device has pending updates
            if device.get('pendingUpdates', False):
                stats['pending'] += 1

        return stats 