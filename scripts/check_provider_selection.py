#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to check provider selection field values in Odoo 17
Run this in the Odoo shell with:
    python odoo-bin shell -c /path/to/odoo.conf -d your_database --addons-path=/path/to/addons
Then execute:
    exec(open('scripts/check_provider_selection.py').read())
"""

import logging
_logger = logging.getLogger(__name__)

print("=== Checking Provider Selection Field Values ===")

# Get the IAP account model
IapAccount = env['iap.account']

# First, check what modules are installed that might affect the provider field
iap_module = env['ir.module.module'].search([('name', '=', 'iap')])
iap_alt_module = env['ir.module.module'].search([('name', '=', 'iap_alternative_provider')])
print(f"IAP module: {iap_module.name} - State: {iap_module.state}")
print(f"IAP Alternative Provider module: {iap_alt_module.name if iap_alt_module else 'Not found'} - State: {iap_alt_module.state if iap_alt_module else 'N/A'}")

# Check provider field
provider_field = IapAccount._fields.get('provider')
if provider_field:
    print("\nProvider field information:")
    print(f"  Field type: {provider_field.type}")
    print(f"  Selection values: {provider_field.selection}")
    # Check if our value is in the selection
    selection_values = [value for value, label in provider_field.selection]
    print(f"  'sms_api_gatewayapi' in selection values: {'sms_api_gatewayapi' in selection_values}")
else:
    print("\nProvider field not found in the IAP Account model")
    
# Try to create a test account with our provider value
print("\nAttempting to create a test account with provider='sms_api_gatewayapi'...")
try:
    test_account = env['iap.account'].with_context(test_check=True).create({
        'name': 'TEST_GATEWAYAPI',
        'service_name': 'sms',
        'provider': 'sms_api_gatewayapi',
        'gatewayapi_base_url': 'https://gatewayapi.eu',
        'gatewayapi_sender': 'Odoo',
    })
    print(f"SUCCESS! Created test account with ID {test_account.id}")
    print(f"Provider value: {test_account.provider}")
    # Clean up
    print("Cleaning up test account...")
    test_account.unlink()
except Exception as e:
    print(f"FAILED to create test account: {e}")

# Check existing accounts
print("\nChecking existing accounts:")
accounts = env['iap.account'].search([])
for account in accounts:
    print(f"  - {account.name}: provider={account.provider}, service={account.service_name}")

print("\nDone!") 