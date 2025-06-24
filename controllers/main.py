# -*- coding: utf-8 -*-

import json
import logging
import jwt
from odoo import http
from odoo.http import request, Response


_logger = logging.getLogger(__name__)


class GatewayApiWebhookController(http.Controller):

    @http.route(
        '/gatewayapi/dlr',
        type='http',
        auth='public',
        methods=['POST'],
        csrf=False
    )
    def gatewayapi_dlr_webhook(self, **kwargs):
        """Webhook to receive Delivery Reports (DLRs) from GatewayAPI."""
        _logger.debug("GatewayAPI DLR: Received webhook with headers: %s",
                      dict(request.httprequest.headers))

        jwt_secret = request.env['ir.config_parameter'].sudo().get_param(
            'gatewayapi.webhook_jwt_secret'
        )
        if not jwt_secret:
            _logger.error(
                "GatewayAPI DLR: JWT secret not configured in system "
                "parameters"
            )
            return Response(
                json.dumps({
                    'status': 'error',
                    'message': (
                        'JWT secret not configured. ' +
                        'Please set gatewayapi.webhook_jwt_secret parameter.'
                    )
                }),
                status=500,
                mimetype='application/json'
            )

        # Check if JWT verification is required
        require_jwt = request.env['ir.config_parameter'].sudo().get_param(
            'gatewayapi.webhook_require_jwt', 'true'
        ).lower() == 'true'

        auth_header = request.httprequest.headers.get('X-Gwapi-Signature')
        if not auth_header:
            if require_jwt:
                _logger.warning(
                    'GatewayAPI DLR: Missing X-Gwapi-Signature header. '
                    'Please ensure GatewayAPI is configured to send this '
                    'header.'
                )
                return Response(
                    json.dumps({
                        'status': 'error',
                        'message': (
                            'Missing X-Gwapi-Signature header. ' +
                            'Please configure GatewayAPI to send this header.'
                        )
                    }),
                    status=401,
                    mimetype='application/json'
                )
            else:
                _logger.debug(
                    'GatewayAPI DLR: Missing X-Gwapi-Signature header. '
                    'JWT verification is disabled.'
                )
        else:
            # Verify JWT if header is present
            try:
                token = auth_header
                jwt.decode(token, jwt_secret, algorithms=['HS256'])
                _logger.info("GatewayAPI DLR: JWT verified successfully.")

            except jwt.ExpiredSignatureError:
                _logger.warning("GatewayAPI DLR: JWT verification failed - "
                                "ExpiredSignatureError.")
                return Response(
                    json.dumps({
                        'status': 'error',
                        'message': 'Token has expired. ' +
                                   'Please check GatewayAPI configuration.'
                    }),
                    status=401,
                    mimetype='application/json'
                )
            except jwt.InvalidTokenError as e:
                _logger.warning("GatewayAPI DLR: JWT verification failed - "
                                "InvalidTokenError: %s", str(e))
                return Response(
                    json.dumps({
                        'status': 'error',
                        'message': (
                            'Invalid token. ' +
                            'Please check GatewayAPI configuration and JWT '
                            'secret.'
                        )
                    }),
                    status=403,
                    mimetype='application/json'
                )
            except Exception as e:
                _logger.error("GatewayAPI DLR: An unexpected error occurred "
                              "during JWT verification: %s", str(e))
                return Response(
                    json.dumps({
                        'status': 'error',
                        'message': 'Error during token verification. ' +
                                   'Please check server logs.'
                    }),
                    status=503,
                    mimetype='application/json'
                )

        try:
            _logger.info("GatewayAPI DLR: Attempting to parse JSON data from "
                         "request")
            data = request.get_json_data()
            _logger.info("GatewayAPI DLR: Successfully parsed JSON data: %s", 
                         data)
            if not data:
                _logger.error("GatewayAPI DLR: Empty JSON data received")
                return Response(
                    json.dumps({
                        'status': 'error',
                        'message': 'Empty JSON data received'
                    }),
                    status=400,
                    mimetype='application/json'
                )
        except Exception as e:
            _logger.error("GatewayAPI DLR: Failed to parse JSON data: %s", 
                          str(e))
            return Response(
                json.dumps({
                    'status': 'error',
                    'message': 'Invalid JSON data received'
                }),
                status=400,
                mimetype='application/json'
            )

        if not all(k in data for k in ['id', 'status']):
            _logger.warning("GatewayAPI DLR: Missing required fields in "
                            "payload. Data: %s", data)
            return Response(
                json.dumps({
                    'status': 'error',
                    'message': ('Missing required fields (id, status) in '
                                'payload')
                }),
                status=400,
                mimetype='application/json'
            )

        gw_message_id = data.get('id')
        status = data.get('status')
        error = data.get('error')

        _logger.info(
            "GatewayAPI DLR Webhook received data%s: %s for message ID %s",
            " (JWT verified)" if auth_header else "",
            json.dumps(data), gw_message_id
        )

        SmsMessage = request.env['sms.sms'].sudo()
        sms_message = SmsMessage.search(
            [('gatewayapi_message_id', '=', str(gw_message_id))], limit=1
        )

        if not sms_message:
            _logger.warning(
                "GatewayAPI DLR: No sms.sms record found for "
                "gatewayapi_message_id: %s",
                gw_message_id
            )
            return Response(
                json.dumps({
                    'status': 'ok',
                    'message': 'SMS not found but acknowledged'
                }),
                status=200,
                mimetype='application/json')

        original_odoo_state = sms_message.state
        new_odoo_state = original_odoo_state
        failure_type = sms_message.failure_type

        if status == 'DELIVERED':
            new_odoo_state = 'sent'
            failure_type = False
        elif status == 'ACCEPTED':
            new_odoo_state = 'sent'
            failure_type = False
        elif status == 'UNDELIVERABLE':
            new_odoo_state = 'error'
            failure_type = 'sms_unregistered'
        elif status == 'REJECTED':
            new_odoo_state = 'error'
            failure_type = 'sms_blacklist'
        elif status in ['EXPIRED', 'SKIPPED']:
            new_odoo_state = 'error'
            failure_type = 'sms_other'

        if (new_odoo_state != original_odoo_state or 
                failure_type != sms_message.failure_type):
            sms_message.write({
                'state': new_odoo_state,
                'failure_type': failure_type,
                'sms_api_error': error if error else False
            })
            _logger.info(
                "GatewayAPI DLR: Updated SMS %s state from %s to %s "
                "(GatewayAPI status: %s)",
                gw_message_id, original_odoo_state, new_odoo_state, status
            )

        return Response(
            json.dumps({
                'status': 'ok',
                'message': 'Webhook processed successfully'
            }),
            status=200,
            mimetype='application/json')
