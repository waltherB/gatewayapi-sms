#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test script to verify that the notification action is properly set
when the 'Check for minimum credits' checkbox is enabled.

Usage:
    This script should be run from the Odoo shell:
    
    odoo shell -d your_database -c your_config_file --no-http
    
    Then in the shell:
    
    exec(open('/path/to/this/script.py').read())
"""

import logging
_logger = logging.getLogger(__name__)

# Get the IAP account
iap_account = env['iap.account'].search([
    '|',
    ('provider', '=', 'sms_api_gatewayapi'),
    '&',
    ('service_name', '=', 'sms'), 
    ('gatewayapi_base_url', '!=', False)
], limit=1)

if not iap_account:
    _logger.error("No GatewayAPI account found")
    exit()

# Print current state
_logger.info("Current state:")
_logger.info(f"Account ID: {iap_account.id}")
_logger.info(f"Check for minimum credits: {iap_account.gatewayapi_check_min_tokens}")
_logger.info(f"Notification action: {iap_account.gatewayapi_token_notification_action.id if iap_account.gatewayapi_token_notification_action else 'Not set'}")

# Get the notification action
try:
    notification_action = env.ref('gatewayapi_sms.low_credits_notification_action')
    _logger.info(f"Found notification action with ID: {notification_action.id}")
except Exception as e:
    _logger.error(f"Failed to find notification action: {e}")
    exit()

# Enable the 'Check for minimum credits' checkbox
iap_account.write({
    'gatewayapi_check_min_tokens': True,
    'gatewayapi_min_tokens': 100  # Set a minimum token value
})

# Check if the notification action was set
_logger.info("After enabling 'Check for minimum credits':")
_logger.info(f"Check for minimum credits: {iap_account.gatewayapi_check_min_tokens}")
_logger.info(f"Notification action: {iap_account.gatewayapi_token_notification_action.id if iap_account.gatewayapi_token_notification_action else 'Not set'}")

# If the notification action was not set, set it manually
if not iap_account.gatewayapi_token_notification_action:
    _logger.warning("Notification action was not set automatically. Setting it manually.")
    iap_account.write({
        'gatewayapi_token_notification_action': notification_action.id
    })
    _logger.info(f"Notification action now set to: {iap_account.gatewayapi_token_notification_action.id}")
else:
    _logger.info("Notification action was set automatically as expected.")

# Test the credit balance check
_logger.info("Testing credit balance check...")
env['iap.account'].check_gatewayapi_credit_balance()
_logger.info("Credit balance check completed.")
