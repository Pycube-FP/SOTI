from flask import Blueprint, render_template, jsonify, request, current_app
from app.services.soti_service import SotiService
from app.utils.decorators import login_required
from typing import Dict, List, Optional

# Create blueprint
devices_bp = Blueprint('devices', __name__)
soti_service = SotiService()

@devices_bp.route('/devices')
@login_required
def devices_page() -> str:
    """
    Render the devices page with initial device data.
    """
    try:
        devices_data = soti_service.get_devices()
        return render_template('main/devices.html', soti_devices=devices_data)
    except Exception as e:
        # Log the error
        current_app.logger.error(f"Error loading devices page: {str(e)}")
        # Return error page or redirect
        return render_template('error.html', error="Failed to load devices"), 500

@devices_bp.route('/api/devices/<device_id>')
@login_required
def get_device_details(device_id: str):
    """
    Get detailed information for a specific device.
    """
    try:
        current_app.logger.debug(f"Fetching details for device ID: {device_id}")
        
        # Get device details from SOTI API
        device = soti_service.get_device_details(device_id)
        
        if not device:
            current_app.logger.error(f"Device not found: {device_id}")
            return jsonify({'error': 'Device not found'}), 404
            
        # Transform the device data to match the expected format
        transformed_device = {
            'id': device.get('DeviceId') or device.get('Id') or device_id,
            'name': device.get('DeviceName') or device.get('Name') or 'Unknown Device',
            'status': 'Online' if device.get('IsAgentOnline', False) else 'Offline',
            'model': device.get('Model') or device.get('DeviceModel') or 'Unknown Model',
            'manufacturer': device.get('Manufacturer') or 'Unknown Manufacturer',
            'osVersion': (
                device.get('OSVersion') or 
                device.get('OsVersion') or 
                device.get('OperatingSystem') or 
                device.get('OS') or 
                'Unknown OS'
            ),
            'SerialNumber': (
                device.get('HardwareSerialNumber') or
                device.get('MobileSerialNumber') or
                device.get('SerialNumber') or
                device.get('Serial') or
                device.get('DeviceSerial') or
                device.get('HardwareId') or
                device.get('IMEI_MEID_ESN') or
                'Unknown SN'
            ),
            'lastSeen': device.get('LastSeen') or device.get('LastSeenTime'),
            'lastUpdated': device.get('LastUpdated') or device.get('LastUpdateTime')
        }
        
        current_app.logger.debug(f"Raw device data: {device}")
        current_app.logger.debug(f"Transformed device data: {transformed_device}")
        return jsonify(transformed_device)
    except Exception as e:
        current_app.logger.error(f"Error getting device details: {str(e)}")
        return jsonify({'error': 'Failed to get device details'}), 500

@devices_bp.route('/api/devices/refresh', methods=['POST'])
@login_required
def refresh_devices():
    """
    Refresh all devices.
    """
    try:
        devices_data = soti_service.refresh_devices()
        return jsonify(devices_data)
    except Exception as e:
        current_app.logger.error(f"Error refreshing devices: {str(e)}")
        return jsonify({'error': 'Failed to refresh devices'}), 500

@devices_bp.route('/api/devices/<device_id>/refresh', methods=['POST'])
@login_required
def refresh_device(device_id: str):
    """
    Refresh a specific device.
    """
    try:
        devices_data = soti_service.refresh_device(device_id)
        return jsonify(devices_data)
    except Exception as e:
        current_app.logger.error(f"Error refreshing device: {str(e)}")
        return jsonify({'error': f'Failed to refresh device {device_id}'}), 500 