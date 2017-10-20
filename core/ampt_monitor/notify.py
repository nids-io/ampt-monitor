'''
AMPT Manager event notification handling

'''
import hmac
import json
import time
import logging

import requests

from . import __application_name__


logger = logging.getLogger(__application_name__)

def notify_manager(url, evt, hmac_params, verify_cert):
    '''Notify AMPT Manager of new healthcheck event.

    :param url:         AMPT Manager URL
    :param evt:         Parsed event data dict from monitor plugin
    :param hmac_params: dictionary containing keys for HMAC key and
                        digest to use
    :return:

    '''
    # XXX If cert validation disabled, squash underlying warnings also. This
    # is oversilencing so a better approach is probably required.
    if not verify_cert:
        import urllib3
        urllib3.disable_warnings()

    # Append timestamp counter to request parameters
    evt.update(ts=str(time.time()))

    # HMAC: build message from unindented, key-sorted JSON of parameters
    j = json.dumps(evt, sort_keys=True)
    # Compute with auth key and message digest from configuration
    h = hmac.new(bytes(hmac_params['key'].encode('utf-8')),
                 j.encode('utf-8'), hmac_params['hash'])
    logger.debug('event log JSON object: %s', j)

    # Append HMAC hex digest to request parameters
    evt.update(h=h.hexdigest())

    logger.info('sending AMPT Manager new event log for monitor ID %s...',
                 evt['monitor'])
    logger.debug('event log object pending delivery to AMPT Manager: %s', evt)
    try:
        r = requests.post(url, data=evt, verify=verify_cert)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error('failure notifying AMPT Manager of new event log: %s', e)
        return

    logger.info('AMPT Manager returned status %s: %s',
                r.status_code, r.json().get('message'))

