#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test script to verify GatewayAPI webhook configuration.
This script checks:
1. If the JWT secret is configured in Odoo
2. If the webhook URL is properly configured
3. Simulates a webhook call to test the endpoint

Usage:
    python3 test_webhook_config.py
"""

import os
import sys
import json
import requests
import logging
from datetime import datetime
import jwt
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def normalize_url(url):
    """Ensure URL has the correct scheme."""
    parsed = urlparse(url)
    if not parsed.scheme:
        # If no scheme is provided, use https
        url = f"https://{url}"
    elif parsed.scheme == 'http':
        # Convert http to https
        url = url.replace('http://', 'https://', 1)
    return url

def get_odoo_config():
    """Get Odoo configuration from environment variables."""
    odoo_url = os.getenv('ODOO_URL', 'https://localhost:8069')
    odoo_db = os.getenv('ODOO_DB', '')
    odoo_user = os.getenv('ODOO_USER', 'admin')
    odoo_password = os.getenv('ODOO_PASSWORD', 'admin')
    odoo_api_key = os.getenv('ODOO_API_KEY', '')
    
    if not odoo_db:
        logger.error("ODOO_DB environment variable not set")
        sys.exit(1)
    
    # Normalize URL to use HTTPS
    odoo_url = normalize_url(odoo_url)
    
    return {
        'url': odoo_url,
        'db': odoo_db,
        'username': odoo_user,
        'password': odoo_password,
        'api_key': odoo_api_key
    }

def check_jwt_secret(config):
    """Check if JWT secret is configured in Odoo."""
    try:
        # Authenticate with Odoo
        session = requests.Session()
        auth_url = f"{config['url']}/jsonrpc"
        auth_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'common',
                'method': 'login',
                'args': [
                    config['db'],
                    config['username'],
                    config['api_key'] if config['api_key'] else config['password']
                ]
            }
        }
        
        logger.info(f"Attempting to authenticate at {auth_url}")
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Disable SSL verification if needed
        verify_ssl = os.getenv('VERIFY_SSL', 'true').lower() == 'true'
        if not verify_ssl:
            logger.warning("SSL verification is disabled")
        
        response = session.post(
            auth_url, 
            json=auth_data, 
            headers=headers,
            verify=verify_ssl
        )
        
        if response.status_code != 200:
            logger.error(f"Authentication failed with status {response.status_code}")
            logger.error(f"Response: {response.text}")
            return None
            
        login_result = response.json()
        logger.info(f"Raw API response for authentication: {login_result}")
        
        if not login_result.get('result'):
            logger.error(f"Failed to log in: {login_result.get('error', {}).get('message', 'Unknown error')}")
            return None

        uid = login_result['result']

        # Get JWT secret from system parameters
        search_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute_kw',
                'args': [
                    config['db'],
                    uid,
                    config['api_key'] if config['api_key'] else config['password'],
                    'ir.config_parameter',
                    'search_read',
                    [[('key', '=', 'gatewayapi.webhook_jwt_secret')], ['key', 'value']]
                ]
            }
        }
        
        logger.info("Checking for JWT secret in system parameters")
        response = session.post(
            auth_url, 
            json=search_data, 
            headers=headers,
            verify=verify_ssl
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to search system parameters: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return None
            
        result = response.json()
        logger.info(f"Raw API response for JWT secret search: {result}")
        
        if result.get('result'):
            secret = result['result'][0]['value']
            if secret:
                logger.info("✅ JWT secret is configured")
                return secret
            else:
                logger.error("❌ JWT secret is empty")
        else:
            logger.error("❌ JWT secret not found in system parameters")
            logger.info("Please set the JWT secret in Odoo:")
            logger.info("1. Go to Settings > Technical > Parameters > System Parameters")
            logger.info("2. Create parameter with key 'gatewayapi.webhook_jwt_secret'")
            logger.info("3. Set the value to your GatewayAPI webhook secret")
        
    except requests.exceptions.SSLError as e:
        logger.error(f"SSL Error: {str(e)}")
        logger.error("If you're using a self-signed certificate, set VERIFY_SSL=false")
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error: {str(e)}")
        logger.error("Please check if your Odoo instance is accessible")
    except Exception as e:
        logger.error(f"Error checking JWT secret: {str(e)}")
    
    return None

def test_webhook_endpoint(config, jwt_secret):
    """Test the webhook endpoint with a simulated DLR."""
    if not jwt_secret:
        logger.error("Cannot test webhook without JWT secret")
        return
    
    try:
        # Create a test JWT token
        # Convert to integer Unix timestamps for JWT
        current_time_utc = int(datetime.utcnow().timestamp())
        expiry_time_utc = current_time_utc + (24 * 3600)
        payload = {
            'iat': current_time_utc,
            'exp': expiry_time_utc,  # 24 hours expiry
            'iss': 'gatewayapi'
        }
        token = jwt.encode(payload, jwt_secret, algorithm='HS256')
        logger.info(f"JWT 'iat' (issued at): {datetime.fromtimestamp(current_time_utc)} UTC ({current_time_utc})")
        logger.info(f"JWT 'exp' (expires at): {datetime.fromtimestamp(expiry_time_utc)} UTC ({expiry_time_utc})")
        
        # Prepare test DLR data
        dlr_data = {
            'id': '8001907829504',  # Example message ID
            'status': 'DELIVERED',
            'msisdn': '+4712345678',
            'time': datetime.utcnow().isoformat(),
            'userref': 'test-uuid'
        }
        
        # Send test webhook
        webhook_url = f"{config['url']}/gatewayapi/dlr"
        headers = {
            'Content-Type': 'application/json',
            'X-Gwapi-Signature': token
        }
        
        # Disable SSL verification if needed
        verify_ssl = os.getenv('VERIFY_SSL', 'true').lower() == 'true'
        
        logger.info(f"Sending test webhook to {webhook_url}")
        response = requests.post(
            webhook_url, 
            json=dlr_data, 
            headers=headers,
            verify=verify_ssl
        )
        
        if response.status_code == 200:
            logger.info("✅ Webhook test successful")
            logger.info(f"Response: {response.json()}")
        else:
            logger.error(f"❌ Webhook test failed with status {response.status_code}")
            logger.error(f"Response: {response.text}")
            
    except requests.exceptions.SSLError as e:
        logger.error(f"SSL Error during webhook test: {str(e)}")
        logger.error("If you're using a self-signed certificate, set VERIFY_SSL=false")
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during webhook test: {str(e)}")
    except Exception as e:
        logger.error(f"Error testing webhook: {str(e)}")

def main():
    """Main function to run the tests."""
    logger.info("Starting GatewayAPI webhook configuration test")
    
    # Get Odoo configuration
    config = get_odoo_config()
    logger.info(f"Testing against Odoo instance: {config['url']}")
    
    # Check JWT secret
    jwt_secret = check_jwt_secret(config)
    
    # Test webhook endpoint
    if jwt_secret:
        test_webhook_endpoint(config, jwt_secret)
    
    logger.info("Test completed")

if __name__ == '__main__':
    main() 