from flask import render_template, redirect, url_for, current_app, session, request, flash, send_file, jsonify
from flask_login import login_required, current_user
from app.main import bp
import msal
import os
import requests
import pandas as pd
from datetime import datetime
import io
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email
import urllib.parse
import json
import secrets
from app.utils.soti_client import SotiClient
from app.services.soti_service import SotiService

# Create singleton instance
soti_service = SotiService()

def validate_token(token, service_name):
    if not token:
        current_app.logger.warning(f"No token found for {service_name}")
        return False
        
    try:
        # Make a simple API call to check token validity
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Use different endpoints for each service
        endpoints = {
            'teams': 'https://graph.microsoft.com/v1.0/me',
            'outlook': 'https://graph.microsoft.com/v1.0/me',
            'onedrive': 'https://graph.microsoft.com/v1.0/me'
        }
        
        response = requests.get(endpoints[service_name], headers=headers)
        
        if response.status_code == 200:
            current_app.logger.info(f"Token valid for {service_name}")
            return True
        else:
            current_app.logger.error(f"Token invalid for {service_name}: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        current_app.logger.error(f"Error validating {service_name} token: {str(e)}")
        return False

class TeamsNotificationForm(FlaskForm):
    channel = SelectField('Channel', choices=[
        ('general', 'General'),
        ('lab-updates', 'Lab Updates'),
        ('sample-alerts', 'Sample Alerts'),
        ('urgent-notifications', 'Urgent Notifications')
    ], validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])
    priority = SelectField('Priority', choices=[
        ('normal', 'Normal'),
        ('high', 'High'),
        ('urgent', 'Urgent')
    ])

class EmailForm(FlaskForm):
    to = StringField('To', validators=[DataRequired(), Email()])
    subject = StringField('Subject', validators=[DataRequired()])
    body = TextAreaField('Message', validators=[DataRequired()])
    priority = SelectField('Priority', choices=[
        ('normal', 'Normal'),
        ('high', 'High'),
        ('urgent', 'Urgent')
    ])

@bp.route('/')
@bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page"""
    teams_form = TeamsNotificationForm()
    email_form = EmailForm()
    
    # Get SOTI devices if authenticated
    soti_devices = {'devices': [], 'stats': {'online': 0, 'offline': 0, 'pending': 0, 'total': 0}}
    if bool(session.get('soti_token')):
        try:
            soti_creds = session.get('soti_credentials')
            if soti_creds:
                soti_client = SotiClient(
                    server_url=soti_creds['server_url'],
                    client_id=soti_creds['client_id'],
                    client_secret=soti_creds['client_secret'],
                    username=soti_creds['username'],
                    password=soti_creds['password']
                )
                soti_devices = soti_client.get_devices()
        except Exception as e:
            current_app.logger.error(f"Error fetching SOTI devices for dashboard: {str(e)}")
            current_app.logger.debug("Exception details:", exc_info=True)
    
    return render_template('main/dashboard.html', 
                         form=teams_form, 
                         email_form=email_form,
                         soti_devices=soti_devices)

@bp.route('/connectors')
@login_required
def connectors():
    # Check authentication status for each service
    auth_status = {
        'teams': validate_token(session.get('teams_token'), 'teams'),
        'outlook': validate_token(session.get('outlook_token'), 'outlook'),
        'onedrive': validate_token(session.get('onedrive_token'), 'onedrive'),
        'slack': bool(session.get('slack_token')),
        'jira': bool(session.get('jira_token')),
        'soti': bool(session.get('soti_token')),
        'dropbox': bool(session.get('dropbox_token'))
    }
    
    current_app.logger.info(f"Auth status for connectors: {auth_status}")
    return render_template('main/connectors.html', auth_status=auth_status)

@bp.route('/auth/teams')
@login_required
def teams_auth():
    try:
        # Initialize MSAL app
        msal_app = msal.ConfidentialClientApplication(
            client_id=current_app.config['MICROSOFT_CLIENT_ID'],
            client_credential=current_app.config['MICROSOFT_CLIENT_SECRET'],
            authority=f"https://login.microsoftonline.com/{current_app.config['MICROSOFT_TENANT_ID']}"
        )

        # Define scopes for Teams
        scopes = [
            'https://graph.microsoft.com/Mail.Read',
            'https://graph.microsoft.com/Mail.ReadWrite',
            'https://graph.microsoft.com/Calendars.Read',
            'https://graph.microsoft.com/Calendars.ReadWrite',
            'https://graph.microsoft.com/User.Read',
            'https://graph.microsoft.com/Team.ReadBasic.All'
        ]
        
        # Generate authorization URL
        auth_url = msal_app.get_authorization_request_url(
            scopes=scopes,
            redirect_uri=url_for('main.teams_callback', _external=True, _scheme='https'),
            state=session.get('state', '')
        )
        
        current_app.logger.info(f"Generated Teams auth URL: {auth_url}")
        return redirect(auth_url)
    except Exception as e:
        current_app.logger.error(f"Error in Teams auth: {str(e)}")
        flash('Failed to initialize Teams authentication. Please try again.', 'error')
        return redirect(url_for('main.connectors'))

@bp.route('/auth/teams/callback')
@login_required
def teams_callback():
    try:
        # Get authorization code from request
        code = request.args.get('code')
        if not code:
            current_app.logger.error("No authorization code received in Teams callback")
            flash('Authentication failed: No authorization code received.', 'error')
            return redirect(url_for('main.connectors'))

        # Initialize MSAL app
        msal_app = msal.ConfidentialClientApplication(
            client_id=current_app.config['MICROSOFT_CLIENT_ID'],
            client_credential=current_app.config['MICROSOFT_CLIENT_SECRET'],
            authority=f"https://login.microsoftonline.com/{current_app.config['MICROSOFT_TENANT_ID']}"
        )

        # Acquire token
        result = msal_app.acquire_token_by_authorization_code(
            code=code,
            scopes=[
                'https://graph.microsoft.com/Mail.Read',
                'https://graph.microsoft.com/Mail.ReadWrite',
                'https://graph.microsoft.com/Calendars.Read',
                'https://graph.microsoft.com/Calendars.ReadWrite',
                'https://graph.microsoft.com/User.Read',
                'https://graph.microsoft.com/Team.ReadBasic.All'
            ],
            redirect_uri=url_for('main.teams_callback', _external=True, _scheme='https')
        )

        if 'error' in result:
            current_app.logger.error(f"Token acquisition failed: {result.get('error_description', 'Unknown error')}")
            flash('Failed to acquire access token. Please try again.', 'error')
            return redirect(url_for('main.connectors'))

        # Store token in session
        session['teams_token'] = result.get('access_token')
        current_app.logger.info("Successfully stored Teams token in session")
        
        flash('Successfully authenticated with Microsoft Teams!', 'success')
        return redirect(url_for('main.connectors'))
    except Exception as e:
        current_app.logger.error(f"Error in Teams callback: {str(e)}")
        flash('An error occurred during Teams authentication. Please try again.', 'error')
        return redirect(url_for('main.connectors'))

@bp.route('/auth/outlook')
@login_required
def outlook_auth():
    try:
        # Initialize MSAL app
        msal_app = msal.ConfidentialClientApplication(
            client_id=current_app.config['MICROSOFT_CLIENT_ID'],
            client_credential=current_app.config['MICROSOFT_CLIENT_SECRET'],
            authority=f"https://login.microsoftonline.com/{current_app.config['MICROSOFT_TENANT_ID']}"
        )

        # Define scopes for Outlook
        scopes = [
            'https://graph.microsoft.com/Mail.Read',
            'https://graph.microsoft.com/Mail.ReadWrite',
            'https://graph.microsoft.com/Mail.Send',
            'https://graph.microsoft.com/Calendars.Read',
            'https://graph.microsoft.com/Calendars.ReadWrite',
            'https://graph.microsoft.com/User.Read',
            'https://graph.microsoft.com/MailboxSettings.Read',
            'https://graph.microsoft.com/MailboxSettings.ReadWrite'
        ]
        
        # Generate authorization URL
        auth_url = msal_app.get_authorization_request_url(
            scopes=scopes,
            redirect_uri=url_for('main.outlook_callback', _external=True, _scheme='https'),
            state=session.get('state', '')
        )
        
        current_app.logger.info(f"Generated Outlook auth URL: {auth_url}")
        return redirect(auth_url)
    except Exception as e:
        current_app.logger.error(f"Error in Outlook auth: {str(e)}")
        flash('Failed to initialize Outlook authentication. Please try again.', 'error')
        return redirect(url_for('main.connectors'))

def refresh_outlook_token():
    """Refresh the Outlook access token using refresh token"""
    try:
        # Initialize MSAL app
        msal_app = msal.ConfidentialClientApplication(
            client_id=current_app.config['MICROSOFT_CLIENT_ID'],
            client_credential=current_app.config['MICROSOFT_CLIENT_SECRET'],
            authority=f"https://login.microsoftonline.com/{current_app.config['MICROSOFT_TENANT_ID']}"
        )

        # Get refresh token from session
        refresh_token = session.get('outlook_refresh_token')
        if not refresh_token:
            current_app.logger.error("No refresh token found for Outlook")
            return False

        # Acquire new token using refresh token
        result = msal_app.acquire_token_by_refresh_token(
            refresh_token,
            scopes=[
                'https://graph.microsoft.com/Mail.Read',
                'https://graph.microsoft.com/Mail.ReadWrite',
                'https://graph.microsoft.com/Calendars.Read',
                'https://graph.microsoft.com/Calendars.ReadWrite',
                'https://graph.microsoft.com/User.Read',
                'https://graph.microsoft.com/MailboxSettings.Read',
                'https://graph.microsoft.com/MailboxSettings.ReadWrite'
            ]
        )

        if 'error' in result:
            current_app.logger.error(f"Token refresh failed: {result.get('error_description', 'Unknown error')}")
            return False

        # Update session with new tokens
        session['outlook_token'] = result.get('access_token')
        session['outlook_refresh_token'] = result.get('refresh_token')
        
        current_app.logger.info("Successfully refreshed Outlook token")
        return True

    except Exception as e:
        current_app.logger.error(f"Error refreshing Outlook token: {str(e)}")
        return False

@bp.route('/auth/outlook/callback')
@login_required
def outlook_callback():
    try:
        # Get authorization code from request
        code = request.args.get('code')
        if not code:
            current_app.logger.error("No authorization code received in Outlook callback")
            flash('Authentication failed: No authorization code received.', 'error')
            return redirect(url_for('main.connectors'))

        # Initialize MSAL app
        msal_app = msal.ConfidentialClientApplication(
            client_id=current_app.config['MICROSOFT_CLIENT_ID'],
            client_credential=current_app.config['MICROSOFT_CLIENT_SECRET'],
            authority=f"https://login.microsoftonline.com/{current_app.config['MICROSOFT_TENANT_ID']}"
        )

        # Acquire token with updated scopes
        result = msal_app.acquire_token_by_authorization_code(
            code=code,
            scopes=[
                'https://graph.microsoft.com/Mail.Read',
                'https://graph.microsoft.com/Mail.ReadWrite',
                'https://graph.microsoft.com/Mail.Send',
                'https://graph.microsoft.com/Calendars.Read',
                'https://graph.microsoft.com/Calendars.ReadWrite',
                'https://graph.microsoft.com/User.Read',
                'https://graph.microsoft.com/MailboxSettings.Read',
                'https://graph.microsoft.com/MailboxSettings.ReadWrite'
            ],
            redirect_uri=url_for('main.outlook_callback', _external=True, _scheme='https')
        )

        if 'error' in result:
            current_app.logger.error(f"Token acquisition failed: {result.get('error_description', 'Unknown error')}")
            flash('Failed to acquire access token. Please try again.', 'error')
            return redirect(url_for('main.connectors'))

        # Store both access token and refresh token in session
        session['outlook_token'] = result.get('access_token')
        session['outlook_refresh_token'] = result.get('refresh_token')
        current_app.logger.info("Successfully stored Outlook tokens in session")
        
        flash('Successfully authenticated with Outlook!', 'success')
        return redirect(url_for('main.connectors'))
    except Exception as e:
        current_app.logger.error(f"Error in Outlook callback: {str(e)}")
        flash('An error occurred during Outlook authentication. Please try again.', 'error')
        return redirect(url_for('main.connectors'))

@bp.route('/auth/onedrive')
@login_required
def onedrive_auth():
    try:
        current_app.logger.info("Starting OneDrive authentication process")
        
        # Initialize MSAL app
        msal_app = msal.ConfidentialClientApplication(
            client_id=current_app.config['MICROSOFT_CLIENT_ID'],
            client_credential=current_app.config['MICROSOFT_CLIENT_SECRET'],
            authority=f"https://login.microsoftonline.com/{current_app.config['MICROSOFT_TENANT_ID']}"
        )
        current_app.logger.info("MSAL app initialized successfully")

        # Define scopes for OneDrive
        scopes = [
            'https://graph.microsoft.com/Files.Read',
            'https://graph.microsoft.com/Files.ReadWrite',
            'https://graph.microsoft.com/Files.Read.All',
            'https://graph.microsoft.com/Files.ReadWrite.All',
            'https://graph.microsoft.com/User.Read'
        ]
        current_app.logger.info(f"Requesting scopes: {scopes}")
        
        # Generate authorization URL
        redirect_uri = url_for('main.onedrive_callback', _external=True, _scheme='https')
        current_app.logger.info(f"Redirect URI: {redirect_uri}")
        
        auth_url = msal_app.get_authorization_request_url(
            scopes=scopes,
            redirect_uri=redirect_uri,
            state=session.get('state', '')
        )
        
        current_app.logger.info(f"Generated OneDrive auth URL: {auth_url}")
        return redirect(auth_url)
    except Exception as e:
        current_app.logger.error(f"Error in OneDrive auth: {str(e)}", exc_info=True)
        flash('Failed to initialize OneDrive authentication. Please try again.', 'error')
        return redirect(url_for('main.connectors'))

@bp.route('/auth/onedrive/callback')
@login_required
def onedrive_callback():
    try:
        current_app.logger.info("Starting OneDrive callback process")
        
        # Get authorization code from request
        code = request.args.get('code')
        if not code:
            current_app.logger.error("No authorization code received in OneDrive callback")
            current_app.logger.error(f"Request args: {request.args}")
            flash('Authentication failed: No authorization code received.', 'error')
            return redirect(url_for('main.connectors'))
        current_app.logger.info("Received authorization code")

        # Initialize MSAL app
        msal_app = msal.ConfidentialClientApplication(
            client_id=current_app.config['MICROSOFT_CLIENT_ID'],
            client_credential=current_app.config['MICROSOFT_CLIENT_SECRET'],
            authority=f"https://login.microsoftonline.com/{current_app.config['MICROSOFT_TENANT_ID']}"
        )
        current_app.logger.info("MSAL app initialized for token acquisition")

        # Acquire token
        redirect_uri = url_for('main.onedrive_callback', _external=True, _scheme='https')
        current_app.logger.info(f"Using redirect URI for token acquisition: {redirect_uri}")
        
        result = msal_app.acquire_token_by_authorization_code(
            code=code,
            scopes=[
                'https://graph.microsoft.com/Files.Read',
                'https://graph.microsoft.com/Files.ReadWrite',
                'https://graph.microsoft.com/Files.Read.All',
                'https://graph.microsoft.com/Files.ReadWrite.All',
                'https://graph.microsoft.com/User.Read'
            ],
            redirect_uri=redirect_uri
        )

        if 'error' in result:
            error_msg = f"Token acquisition failed: {result.get('error_description', 'Unknown error')}"
            current_app.logger.error(error_msg)
            current_app.logger.error(f"Full result: {result}")
            flash('Failed to acquire access token. Please try again.', 'error')
            return redirect(url_for('main.connectors'))

        # Store token in session
        session['onedrive_token'] = result.get('access_token')
        current_app.logger.info("Successfully stored OneDrive token in session")
        
        # Validate token immediately
        is_valid = validate_token(session['onedrive_token'], 'onedrive')
        current_app.logger.info(f"Token validation result: {is_valid}")
        
        if is_valid:
            flash('Successfully authenticated with OneDrive!', 'success')
        else:
            flash('Connected to OneDrive but token validation failed. Please try again.', 'warning')
        
        return redirect(url_for('main.connectors'))
    except Exception as e:
        current_app.logger.error(f"Error in OneDrive callback: {str(e)}", exc_info=True)
        flash('An error occurred during OneDrive authentication. Please try again.', 'error')
        return redirect(url_for('main.connectors'))

@bp.route('/auth/jira')
@login_required
def jira_auth():
    """Display JIRA authentication form"""
    return render_template('main/jira_auth.html')

@bp.route('/auth/jira/callback', methods=['POST'])
@login_required
def jira_callback():
    """Handle JIRA authentication form submission"""
    try:
        jira_url = request.form.get('jira_url')
        username = request.form.get('username')
        api_token = request.form.get('api_token')

        if not all([jira_url, username, api_token]):
            flash('All fields are required.', 'error')
            return redirect(url_for('main.jira_auth'))

        # Store credentials in session
        session['jira_credentials'] = {
            'jira_url': jira_url,
            'username': username,
            'api_token': api_token
        }
        session['jira_token'] = 'authenticated'  # Set a token to indicate authentication
        session['jira_user'] = username  # Store username for display

        current_app.logger.info('JIRA authentication successful')
        flash('JIRA connector configured successfully.', 'success')
        return redirect(url_for('main.connectors'))
    except Exception as e:
        current_app.logger.error(f"JIRA authentication error: {str(e)}")
        flash('Failed to configure JIRA connector. Please try again.', 'error')
        return redirect(url_for('main.jira_auth'))

@bp.route('/check-auth')
@login_required
def check_auth():
    """Check authentication status for all connectors"""
    auth_status = {
        'teams': validate_token(session.get('teams_token'), 'teams'),
        'outlook': validate_token(session.get('outlook_token'), 'outlook'),
        'onedrive': validate_token(session.get('onedrive_token'), 'onedrive'),
        'soti': bool(session.get('soti_token')),
        'jira': bool(session.get('jira_token'))
    }
    
    current_app.logger.info(f"Auth status: {auth_status}")
    return render_template('main/auth_status.html', auth_status=auth_status)

@bp.route('/revoke-auth/<service>')
@login_required
def revoke_auth(service):
    """Revoke authentication for a specific service"""
    try:
        if service == 'teams':
            session.pop('teams_token', None)
            session.pop('teams_user', None)
        elif service == 'outlook':
            session.pop('outlook_token', None)
            session.pop('outlook_user', None)
        elif service == 'onedrive':
            session.pop('onedrive_token', None)
            session.pop('onedrive_user', None)
        elif service == 'soti':
            session.pop('soti_token', None)
            session.pop('soti_credentials', None)
            session.pop('soti_user', None)
        elif service == 'jira':
            session.pop('jira_token', None)
            session.pop('jira_credentials', None)
            session.pop('jira_user', None)
        elif service == 'dropbox':
            # Revoke Dropbox token
            token = session.get('dropbox_token')
            if token:
                try:
                    requests.post(
                        'https://api.dropboxapi.com/2/auth/token/revoke',
                        headers={'Authorization': f'Bearer {token}'}
                    )
                except:
                    pass  # Ignore errors during revocation
            
            session.pop('dropbox_token', None)
            session.pop('dropbox_refresh_token', None)
            session.pop('dropbox_user', None)
            session.pop('dropbox_state', None)
        
        current_app.logger.info(f"Successfully revoked {service} authentication")
        flash(f'{service.title()} authentication revoked successfully.', 'success')
    except Exception as e:
        current_app.logger.error(f"Error revoking {service} authentication: {str(e)}")
        flash(f'Error revoking {service} authentication.', 'error')
    
    return redirect(url_for('main.connectors'))

@bp.route('/auth/soti')
@login_required
def soti_auth():
    """Configure SOTI connector using environment variables"""
    try:
        # Get credentials from environment variables
        server_url = current_app.config.get('SOTI_SERVER_URL')
        client_id = current_app.config.get('SOTI_CLIENT_ID')
        client_secret = current_app.config.get('SOTI_CLIENT_SECRET')
        username = current_app.config.get('SOTI_USERNAME')
        password = current_app.config.get('SOTI_PASSWORD')
        
        if not all([server_url, client_id, client_secret, username, password]):
            missing = []
            if not server_url: missing.append('SOTI_SERVER_URL')
            if not client_id: missing.append('SOTI_CLIENT_ID')
            if not client_secret: missing.append('SOTI_CLIENT_SECRET')
            if not username: missing.append('SOTI_USERNAME')
            if not password: missing.append('SOTI_PASSWORD')
            current_app.logger.error(f"Missing required environment variables: {', '.join(missing)}")
            flash('SOTI configuration is incomplete. Please check environment variables.', 'error')
            return redirect(url_for('main.connectors'))
        
        # Initialize SOTI client
        current_app.logger.info(f"Initializing SOTI client with server: {server_url}")
        soti_client = SotiClient(server_url, client_id, client_secret, username, password)
        
        # Attempt authentication
        auth_result = soti_client.authenticate()
        
        if auth_result:
            # Store token in session in the same format as other connectors
            session['soti_token'] = soti_client.token
            session['soti_credentials'] = {
                'server_url': server_url,
                'client_id': client_id,
                'client_secret': client_secret,
                'username': username,
                'password': password,
                'token_expiry': soti_client.token_expiry.isoformat() if soti_client.token_expiry else None
            }
            current_app.logger.info("SOTI authentication successful")
            flash('Successfully connected to SOTI MobiControl', 'success')
        else:
            current_app.logger.error("SOTI authentication failed - no token received")
            flash('Failed to connect to SOTI MobiControl. Please check your credentials.', 'error')
        
        return redirect(url_for('main.connectors'))
        
    except Exception as e:
        current_app.logger.error(f"Error during SOTI authentication: {str(e)}")
        current_app.logger.debug("Exception details:", exc_info=True)
        flash('An error occurred while connecting to SOTI MobiControl', 'error')
        return redirect(url_for('main.connectors'))

@bp.route('/export-samples')
@login_required
def export_samples():
    """Export sample data to Excel"""
    try:
        # Create sample data (replace with actual data from your database)
        data = {
            'Sample ID': ['BLD-2024-001', 'URN-2024-002', 'TIS-2024-003'],
            'Type': ['Blood', 'Urine', 'Tissue'],
            'Collection Date': ['2024-03-15', '2024-03-15', '2024-03-14'],
            'Status': ['Processed', 'Pending', 'Failed'],
            'Location': ['Lab 1', 'Lab 2', 'Lab 3']
        }
        
        # Create DataFrame
        df = pd.DataFrame(data)
        
        # Create Excel writer
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Sample Data', index=False)
            
            # Get workbook and worksheet objects
            workbook = writer.book
            worksheet = writer.sheets['Sample Data']
            
            # Define formats
            header_format = workbook.add_format({
                'bold': True,
                'bg_color': '#1F2937',
                'font_color': 'white',
                'border': 1
            })
            
            # Format the header row
            for col_num, value in enumerate(df.columns.values):
                worksheet.write(0, col_num, value, header_format)
            
            # Auto-adjust column widths
            for idx, col in enumerate(df):
                max_length = max(
                    df[col].astype(str).apply(len).max(),
                    len(str(col))
                )
                worksheet.set_column(idx, idx, max_length + 2)
        
        # Seek to the beginning of the stream
        output.seek(0)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'sample_data_{timestamp}.xlsx'
        
        # Return the Excel file
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        current_app.logger.error(f"Error exporting samples: {str(e)}")
        flash('Failed to export sample data. Please try again.', 'error')
        return redirect(url_for('main.dashboard'))

def get_channel_id(channel_name):
    """Get Teams channel ID based on channel name"""
    # Using the specific channel ID from the Teams URL
    channel_mapping = {
        'general': '19:49hGk8ZTLEGzyQ3fbcI732r5RV7PZOkHUtPffqpmJxo1@thread.tacv2',
        'lab-updates': '19:49hGk8ZTLEGzyQ3fbcI732r5RV7PZOkHUtPffqpmJxo1@thread.tacv2',
        'sample-alerts': '19:49hGk8ZTLEGzyQ3fbcI732r5RV7PZOkHUtPffqpmJxo1@thread.tacv2',
        'urgent-notifications': '19:49hGk8ZTLEGzyQ3fbcI732r5RV7PZOkHUtPffqpmJxo1@thread.tacv2'
    }
    return channel_mapping.get(channel_name)

@bp.route('/send-teams-notification', methods=['POST'])
@login_required
def send_teams_notification():
    """Send notification to Teams channel"""
    form = TeamsNotificationForm()
    
    if not form.validate_on_submit():
        flash('Please fill in all required fields.', 'error')
        return redirect(url_for('main.dashboard'))
    
    try:
        # Get Teams token from session
        teams_token = session.get('teams_token')
        if not teams_token:
            flash('Teams authentication required. Please connect Teams first.', 'error')
            return redirect(url_for('main.dashboard'))
        
        # Get channel ID based on selected channel
        channel_id = get_channel_id(form.channel.data)
        if not channel_id:
            flash('Invalid channel selected.', 'error')
            return redirect(url_for('main.dashboard'))
        
        # Prepare message payload
        message_payload = {
            "body": {
                "content": form.message.data
            }
        }
        
        # Add priority indicator if not normal
        if form.priority.data != 'normal':
            priority_emoji = '🔴' if form.priority.data == 'urgent' else '🟡'
            message_payload["body"]["content"] = f"{priority_emoji} **{form.priority.data.upper()}**\n\n{form.message.data}"
        
        # Send message to Teams channel
        headers = {
            'Authorization': f'Bearer {teams_token}',
            'Content-Type': 'application/json'
        }
        
        # Use the specific group ID from the Teams URL
        group_id = '9e7942ba-9fe2-4ec1-a269-2f56a5cc2a07'
        
        response = requests.post(
            f'https://graph.microsoft.com/v1.0/teams/{group_id}/channels/{channel_id}/messages',
            headers=headers,
            json=message_payload
        )
        
        if response.status_code == 201:
            flash('Notification sent successfully!', 'success')
        else:
            current_app.logger.error(f"Failed to send Teams notification: {response.text}")
            flash('Failed to send notification. Please try again.', 'error')
            
    except Exception as e:
        current_app.logger.error(f"Error sending Teams notification: {str(e)}")
        flash('An error occurred while sending the notification.', 'error')
    
    return redirect(url_for('main.dashboard'))

@bp.route('/send-email', methods=['POST'])
@login_required
def send_email():
    """Send email using Microsoft Graph API"""
    form = EmailForm()
    
    if not form.validate_on_submit():
        flash('Please fill in all required fields correctly.', 'error')
        return redirect(url_for('main.dashboard'))
    
    try:
        # Get Outlook token from session
        outlook_token = session.get('outlook_token')
        if not outlook_token:
            flash('Outlook authentication required. Please connect Outlook first.', 'error')
            return redirect(url_for('main.dashboard'))
        
        # Check if token is valid, if not try to refresh it
        if not validate_token(outlook_token, 'outlook'):
            current_app.logger.info("Outlook token expired, attempting to refresh")
            if not refresh_outlook_token():
                flash('Outlook authentication expired. Please reconnect Outlook.', 'error')
                return redirect(url_for('main.connectors'))
            outlook_token = session.get('outlook_token')
        
        # Prepare email payload
        email_payload = {
            "message": {
                "subject": form.subject.data,
                "body": {
                    "contentType": "HTML",
                    "content": form.body.data
                },
                "toRecipients": [
                    {
                        "emailAddress": {
                            "address": form.to.data
                        }
                    }
                ]
            }
        }
        
        # Add priority if not normal
        if form.priority.data != 'normal':
            priority_value = 'high' if form.priority.data == 'high' else 'urgent'
            email_payload["message"]["importance"] = priority_value
        
        # Send email using Microsoft Graph API
        headers = {
            'Authorization': f'Bearer {outlook_token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            'https://graph.microsoft.com/v1.0/me/sendMail',
            headers=headers,
            json=email_payload
        )
        
        if response.status_code == 202:
            flash('Email sent successfully!', 'success')
        else:
            current_app.logger.error(f"Failed to send email: {response.text}")
            flash('Failed to send email. Please try again.', 'error')
            
    except Exception as e:
        current_app.logger.error(f"Error sending email: {str(e)}")
        flash('An error occurred while sending the email.', 'error')
    
    return redirect(url_for('main.dashboard'))

@bp.route('/export-to-onedrive')
@login_required
def export_to_onedrive():
    """Export sample data to OneDrive"""
    try:
        # Get OneDrive token from session
        onedrive_token = session.get('onedrive_token')
        if not onedrive_token:
            flash('OneDrive authentication required. Please connect OneDrive first.', 'error')
            return redirect(url_for('main.dashboard'))

        # Check if token is valid, if not try to refresh it
        if not validate_token(onedrive_token, 'onedrive'):
            current_app.logger.info("OneDrive token expired, attempting to refresh")
            if not refresh_onedrive_token():
                flash('OneDrive authentication expired. Please reconnect OneDrive.', 'error')
                return redirect(url_for('main.connectors'))
            onedrive_token = session.get('onedrive_token')

        # Create Excel file in memory
        output = io.BytesIO()
        workbook = pd.ExcelWriter(output, engine='xlsxwriter')
        
        # Sample data (replace with your actual data)
        sample_data = {
            'Sample ID': ['BLD-2024-001', 'URN-2024-002', 'TIS-2024-003'],
            'Type': ['Blood', 'Urine', 'Tissue'],
            'Collection Date': ['2024-03-15', '2024-03-15', '2024-03-14'],
            'Status': ['Processed', 'Pending', 'Failed'],
            'Location': ['Lab 1', 'Lab 2', 'Lab 3']
        }
        
        df = pd.DataFrame(sample_data)
        df.to_excel(workbook, sheet_name='Sample Activity', index=False)
        
        # Get the xlsxwriter workbook and worksheet objects
        worksheet = workbook.sheets['Sample Activity']
        
        # Add formatting
        header_format = workbook.book.add_format({
            'bold': True,
            'bg_color': '#4B5563',
            'font_color': 'white',
            'border': 1
        })
        
        # Format headers
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)
            worksheet.set_column(col_num, col_num, len(value) + 5)
        
        workbook.close()
        output.seek(0)

        # Generate timestamp for filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'sample_data_{timestamp}.xlsx'

        # Upload to OneDrive
        headers = {
            'Authorization': f'Bearer {onedrive_token}',
            'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        }

        # Upload to OneDrive root folder
        upload_url = 'https://graph.microsoft.com/v1.0/me/drive/root:/Sample Reports/{}:/content'.format(filename)
        
        response = requests.put(
            upload_url,
            headers=headers,
            data=output.getvalue()
        )

        if response.status_code in [200, 201]:
            file_data = response.json()
            web_url = file_data.get('webUrl', '')
            parent_folder = 'Sample Reports'
            flash(f'File successfully exported to OneDrive! Location: {parent_folder}/{filename}. Click <a href="{web_url}" target="_blank" class="text-blue-500 hover:text-blue-700 underline">here</a> to view.', 'success')
        else:
            current_app.logger.error(f"Failed to upload to OneDrive: {response.text}")
            flash('Failed to upload file to OneDrive. Please try again.', 'error')

    except Exception as e:
        current_app.logger.error(f"Error exporting to OneDrive: {str(e)}")
        flash('An error occurred while exporting to OneDrive.', 'error')

    return redirect(url_for('main.dashboard'))

@bp.route('/dropbox-auth')
def dropbox_auth():
    """Initiate Dropbox OAuth flow"""
    try:
        # Check if we have client ID
        if not current_app.config.get('DROPBOX_CLIENT_ID'):
            current_app.logger.error("Dropbox client ID not found in configuration")
            flash('Dropbox client ID is not configured.', 'error')
            return redirect(url_for('main.connectors'))

        # Generate the redirect URI
        redirect_uri = url_for('main.dropbox_callback', _external=True, _scheme='https')
        current_app.logger.info(f"Generated redirect URI: {redirect_uri}")

        # Generate state parameter for CSRF protection
        state = secrets.token_urlsafe(32)
        session['dropbox_oauth_state'] = state

        # Define required scopes including shared folder access
        scopes = (
            "files.content.write "
            "files.content.read "
            "sharing.write "
            "sharing.read "
            "file_requests.write "
            "file_requests.read"
        )
        
        # Construct authorization URL with explicit scopes
        auth_url = (
            'https://www.dropbox.com/oauth2/authorize'
            f'?client_id={current_app.config["DROPBOX_CLIENT_ID"]}'
            f'&redirect_uri={urllib.parse.quote(redirect_uri)}'
            f'&response_type=code'
            f'&token_access_type=offline'
            f'&state={state}'
            f'&scope={urllib.parse.quote(scopes)}'
        )

        current_app.logger.info(f"Redirecting to Dropbox authorization URL with scopes: {scopes}")
        return redirect(auth_url)

    except Exception as e:
        current_app.logger.error(f"Error initiating Dropbox auth: {str(e)}")
        flash('Failed to initiate Dropbox authentication.', 'error')
        return redirect(url_for('main.connectors'))

@bp.route('/auth/dropbox/callback')
@login_required
def dropbox_callback():
    """Handle Dropbox OAuth callback"""
    try:
        current_app.logger.info("Starting Dropbox callback process")
        
        # Verify state parameter
        state = request.args.get('state')
        stored_state = session.get('dropbox_oauth_state')
        current_app.logger.info(f"Received state: {state}, Stored state: {stored_state}")
        
        if state != stored_state:
            current_app.logger.error("State parameter mismatch")
            flash('Invalid state parameter. Please try again.', 'error')
            return redirect(url_for('main.connectors'))
        
        # Get authorization code
        code = request.args.get('code')
        if not code:
            current_app.logger.error("No authorization code received")
            flash('No authorization code received.', 'error')
            return redirect(url_for('main.connectors'))
        
        current_app.logger.info("Received authorization code")
        
        # Exchange code for access token
        token_url = 'https://api.dropboxapi.com/oauth2/token'
        redirect_uri = url_for('main.dropbox_callback', _external=True, _scheme='https')
        
        token_data = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': current_app.config['DROPBOX_CLIENT_ID'],
            'client_secret': current_app.config['DROPBOX_CLIENT_SECRET'],
            'redirect_uri': redirect_uri
        }
        
        current_app.logger.info(f"Attempting to exchange code for token with redirect URI: {redirect_uri}")
        response = requests.post(token_url, data=token_data)
        
        if response.status_code != 200:
            current_app.logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
            flash('Failed to authenticate with Dropbox. Please try again.', 'error')
            return redirect(url_for('main.connectors'))
            
        token_info = response.json()
        current_app.logger.info("Successfully received token response")
        
        # Store tokens in session
        session['dropbox_token'] = token_info['access_token']
        if 'refresh_token' in token_info:
            session['dropbox_refresh_token'] = token_info['refresh_token']
        
        # Test the token with a simple API call
        test_response = requests.post(
            'https://api.dropboxapi.com/2/users/get_current_account',
            headers={'Authorization': f'Bearer {token_info["access_token"]}'}
        )
        
        if test_response.status_code == 200:
            user_info = test_response.json()
            session['dropbox_user'] = user_info.get('email')
            flash('Successfully connected to Dropbox!', 'success')
        else:
            current_app.logger.error(f"Token test failed: {test_response.status_code} - {test_response.text}")
            flash('Connected to Dropbox but token validation failed.', 'warning')
            
    except Exception as e:
        current_app.logger.error(f"Error in Dropbox callback: {str(e)}", exc_info=True)
        flash('An error occurred during Dropbox authentication. Please try again.', 'error')
    
    return redirect(url_for('main.connectors'))

def refresh_dropbox_token():
    """Refresh Dropbox access token"""
    try:
        refresh_token = session.get('dropbox_refresh_token')
        if not refresh_token:
            return False
            
        response = requests.post(
            'https://api.dropboxapi.com/oauth2/token',
            data={
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': current_app.config['DROPBOX_CLIENT_ID'],
                'client_secret': current_app.config['DROPBOX_CLIENT_SECRET']
            }
        )
        
        if response.status_code == 200:
            token_info = response.json()
            session['dropbox_token'] = token_info['access_token']
            session['dropbox_refresh_token'] = token_info.get('refresh_token', refresh_token)
            return True
            
        return False
        
    except Exception as e:
        current_app.logger.error(f"Error refreshing Dropbox token: {str(e)}")
        return False

@bp.route('/export-to-dropbox')
@login_required
def export_to_dropbox():
    """Export sample data to Dropbox app folder"""
    try:
        # Get Dropbox token from session
        dropbox_token = session.get('dropbox_token')
        if not dropbox_token:
            flash('Dropbox authentication required. Please connect Dropbox first.', 'error')
            return redirect(url_for('main.dashboard'))

        # Create Excel file in memory
        output = io.BytesIO()
        workbook = pd.ExcelWriter(output, engine='xlsxwriter')
        
        # Sample data (replace with your actual data)
        sample_data = {
            'Sample ID': ['BLD-2024-001', 'URN-2024-002', 'TIS-2024-003'],
            'Type': ['Blood', 'Urine', 'Tissue'],
            'Collection Date': ['2024-03-15', '2024-03-15', '2024-03-14'],
            'Status': ['Processed', 'Pending', 'Failed'],
            'Location': ['Lab 1', 'Lab 2', 'Lab 3']
        }
        
        df = pd.DataFrame(sample_data)
        df.to_excel(workbook, sheet_name='Sample Activity', index=False)
        
        # Get the xlsxwriter workbook and worksheet objects
        worksheet = workbook.sheets['Sample Activity']
        
        # Add formatting
        header_format = workbook.book.add_format({
            'bold': True,
            'bg_color': '#4B5563',
            'font_color': 'white',
            'border': 1
        })
        
        # Format headers
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)
            worksheet.set_column(col_num, col_num, len(value) + 5)
        
        workbook.close()
        output.seek(0)

        # Generate timestamp for filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'sample_data_{timestamp}.xlsx'

        # Upload to Dropbox app folder
        headers = {
            'Authorization': f'Bearer {dropbox_token}',
            'Content-Type': 'application/octet-stream',
            'Dropbox-API-Arg': json.dumps({
                'path': f'/{filename}',  # Path is relative to app folder
                'mode': 'add',
                'autorename': True,
                'mute': False
            })
        }

        current_app.logger.info("Attempting to upload file to Dropbox app folder")
        
        # Upload to Dropbox using the upload API
        response = requests.post(
            'https://content.dropboxapi.com/2/files/upload',
            headers=headers,
            data=output.getvalue()
        )

        if response.status_code == 200:
            file_data = response.json()
            current_app.logger.info(f"File uploaded successfully: {file_data}")
            
            # Get shared link
            share_response = requests.post(
                'https://api.dropboxapi.com/2/sharing/create_shared_link_with_settings',
                headers={
                    'Authorization': f'Bearer {dropbox_token}',
                    'Content-Type': 'application/json'
                },
                json={
                    'path': file_data['path_display'],
                    'settings': {
                        'requested_visibility': 'public'
                    }
                }
            )
            
            if share_response.status_code in [200, 409]:  # 409 means link already exists
                if share_response.status_code == 409:
                    # Get existing link
                    share_response = requests.post(
                        'https://api.dropboxapi.com/2/sharing/list_shared_links',
                        headers={
                            'Authorization': f'Bearer {dropbox_token}',
                            'Content-Type': 'application/json'
                        },
                        json={
                            'path': file_data['path_display']
                        }
                    )
                
                share_data = share_response.json()
                shared_link = share_data.get('url') if share_response.status_code == 200 else share_data['links'][0]['url']
                flash(f'File successfully exported to Dropbox! Click <a href="{shared_link}" target="_blank" class="text-blue-500 hover:text-blue-700 underline">here</a> to view.', 'success')
            else:
                current_app.logger.error(f"Failed to create shared link: {share_response.text}")
                flash('File uploaded to Dropbox successfully! You can find it in your Dropbox app folder.', 'success')
        else:
            current_app.logger.error(f"Failed to upload to Dropbox: {response.text}")
            flash('Failed to upload file to Dropbox. Please try again.', 'error')

    except Exception as e:
        current_app.logger.error(f"Error exporting to Dropbox: {str(e)}")
        flash('An error occurred while exporting to Dropbox.', 'error')

    return redirect(url_for('main.dashboard'))

@bp.route('/devices')
@login_required
def devices():
    """
    Render the devices page with initial device data.
    """
    try:
        # Check if SOTI configuration is complete
        required_configs = ['SOTI_SERVER_URL', 'SOTI_CLIENT_ID', 'SOTI_CLIENT_SECRET', 'SOTI_USERNAME', 'SOTI_PASSWORD']
        missing_configs = [config for config in required_configs if not current_app.config.get(config)]
        
        if missing_configs:
            error_msg = f"SOTI configuration is incomplete. Missing: {', '.join(missing_configs)}"
            current_app.logger.error(error_msg)
            return render_template('error.html', error=error_msg), 500
        
        current_app.logger.info("Attempting to fetch SOTI devices...")
        devices_data = soti_service.get_devices()
        current_app.logger.info("Successfully fetched SOTI devices")
        return render_template('main/devices.html', soti_devices=devices_data)
    except Exception as e:
        error_msg = str(e)
        current_app.logger.error(f"Error loading devices page: {error_msg}")
        if "configuration is incomplete" in error_msg.lower():
            # Configuration error
            return render_template('error.html', 
                                error="SOTI configuration is incomplete. Please check your environment variables and logs for details."), 500
        elif "failed to authenticate" in error_msg.lower():
            # Authentication error
            return render_template('error.html',
                                error="Failed to authenticate with SOTI. Please check your credentials and try again."), 500
        else:
            # Other errors
            return render_template('error.html',
                                error="Failed to load devices. Please check the application logs for details."), 500

@bp.route('/api/devices/refresh', methods=['POST'])
@login_required
def refresh_devices():
    """
    Refresh all devices and return updated data.
    """
    try:
        devices_data = soti_service.refresh_devices()
        return jsonify(devices_data)
    except Exception as e:
        current_app.logger.error(f"Error refreshing devices: {str(e)}")
        return jsonify({'error': 'Failed to refresh devices'}), 500

@bp.route('/api/devices/<device_id>/refresh', methods=['POST'])
@login_required
def refresh_device(device_id: str):
    """
    Refresh a specific device and return updated data.
    """
    try:
        devices_data = soti_service.refresh_device(device_id)
        return jsonify(devices_data)
    except Exception as e:
        current_app.logger.error(f"Error refreshing device {device_id}: {str(e)}")
        return jsonify({'error': f'Failed to refresh device {device_id}'}), 500

@bp.route('/api/devices/<device_id>', methods=['GET'])
@login_required
def get_device_details(device_id: str):
    """
    Get detailed information for a specific device.
    """
    try:
        device_details = soti_service.get_device_details(device_id)
        if device_details:
            return jsonify(device_details)
        return jsonify({'error': 'Device not found'}), 404
    except Exception as e:
        current_app.logger.error(f"Error fetching device details for {device_id}: {str(e)}")
        return jsonify({'error': 'Failed to fetch device details'}), 500 