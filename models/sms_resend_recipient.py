# -*- coding: utf-8 -*-

from odoo import fields, models

class SmsResendRecipient(models.TransientModel):
    _inherit = "sms.resend.recipient"

    failure_reason = fields.Text(
        related='notification_id.failure_reason', string='Error Description', related_sudo=True, readonly=True)