# -*- coding: utf-8 -*-
{
    'name': "GatewayAPI SMS Connector",
    'summary': "Send SMS with GatewayAPI",
    'author': "Walther Barnett",
    'website': "https://github.com/waltherB/gatewayapi_sms",
    'license': 'AGPL-3',
    'category': 'Tools',
    'version': '17.0.3.0.1',
    'application': False,
    'installable': True,
    'auto_install': False,
    'depends': [
        'base',
        'mail',
        'phone_validation',
        'sms',
        'iap_alternative_provider',
        'iap',
    ],
    'external_dependencies': {
        'python': ['phonenumbers', 'requests', 'pyjwt']
    },
    'data': [
        'security/ir.model.access.csv',
        'data/iap_account_data.xml',
        'data/ir_cron.xml',
        'data/ir_config_parameter_data.xml',
        'views/iap_account.xml',
        'views/sms_sms.xml',
        'views/sms_resend.xml'
    ],
    'images': [
        'static/description/banner.png',
        'static/description/screenshot_01_config.png',
        'static/description/screenshot_02_test_connection.png',
        'static/description/screenshot_03_notification.png',
        'static/description/screenshot_04_balance.png',
        'static/description/Screenshot_05_jwt.png',
    ],
    'description': """\
GatewayAPI SMS Connector for Odoo 17
------------------------------------
Send SMS via GatewayAPI directly from Odoo. This module enhances IAP
    accounts for use with GatewayAPI.

Features include:
- Secure API Token management with a show/hide toggle.
- Credit balance monitoring:
    - Configure minimum credit thresholds per account.
    - Automated periodic checks for low balances.
- Low Credit Notifications:
    - Automatic To-Do activity created for the admin user.
    - Option to send an email alert to a configured email address.
- Per-Account Credit Check Scheduling:
    - Define check frequency (e.g., every 10 minutes, hourly, daily) on
        each IAP account.
    - A master scheduled action (cron job) runs frequently
        (configurable, e.g., every 10 minutes) to trigger checks for
        due accounts based on their individual settings.
- Easy configuration and integration within IAP accounts.
"""
}
