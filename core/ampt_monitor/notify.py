'''
AMPT Manager event notification handling

'''
import logging

import requests

from . import __application_name__


logger = logging.getLogger(__application_name__)

def notify_manager(url, evt, verify_cert):
    '''Notify AMPT Manager of new healthcheck event.

    :param url: AMPT Manager URL
    :param evt: Parsed event data from monitor plugin
    :return:

    '''
    # XXX If cert validation disabled, squash underlying warnings also. This
    # is oversilencing so a better approach probably required.
    if not verify_cert:
        import urllib3
        urllib3.disable_warnings()

    logger.info('sending AMPT Manager new event log for monitor ID %s...',
                 evt['monitor'])
    try:
        r = requests.post(url, data=evt, verify=verify_cert)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error('failure notifying AMPT Manager of new event log: %s', e)

    logger.info('AMPT Manager returned status %s: %s',
                r.status_code, r.json().get('message'))

