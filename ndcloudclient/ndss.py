"""
API client for NDSS server
"""

from typing import *
import random
import string
from base64 import b64encode
from os import path
import requests


from ndcloudclient.ec import sign_ec_signature_for_trust, load_ec_private


class NDSSException(Exception):
    """
    Raises if request to NDSS was failed under any reason
    """
    def __init__(self, description):
        print('NDSS error: ' + str(description))
        super().__init__()


class KeeneticDeviceException(Exception):
    """
    Raises if proxyied request to router was failed under some reason
    """
    code: str
    description: str

    def __init__(self, code, description):
        self.code = code
        self.description = description
        super().__init__()


class NDSS(object):
    """
    Implements methods for NDSS API
    """

    service_id: str = ''
    _server_host: str = ''
    _server_crt_name: str = ''
    _server_timeout: int = 30
    _auth_login: str = ''
    _auth_password: str = ''
    _callback_auth_login: str = ''
    _callback_auth_password: str = ''

    def __init__(self, config: Dict[str, str] = None):
        if isinstance(config, dict):
            self.service_id = config.get('NDSS_SERVICE_ID')
            self._server_host = config.get('NDSS_SERVER')
            self._server_crt_name = config.get('NDSS_CRT')
            self._server_timeout = int(config.get('NDSS_TIMEOUT'))
            self._auth_login = config.get('NDSS_AUTH_BASIC_LOGIN')
            self._auth_password = config.get('NDSS_AUTH_BASIC_PASSWORD')
            self._callback_auth_login = config.get('NDSS_CALLBACK_BASIC_LOGIN')
            self._callback_auth_password = config.get('NDSS_CALLBACK_BASIC_PASSWORD')

    @staticmethod
    def _get_basic_auth_str(login: str, password: str) -> str:
        """
        Returns value of Authorization header for basic authorization
        """
        return 'Basic ' + b64encode(f'{login}:{password}'.encode('utf-8')).decode('utf-8')

    def check_callback_auth(self, authorization_header: str) -> bool:
        """
        Checks, if authorization header matches login and password defined for callback

        :param authorization_header: value of Authorization header
        :return: True or False
        """
        return authorization_header == NDSS._get_basic_auth_str(self._callback_auth_login, self._callback_auth_password)

    def _get_from_ndss(
            self,
            endpoint: str,
            params_get: Dict[str, str]
    ) -> Tuple[Optional[Dict], Optional[int]]:
        """
        Sends GET-request to NDSS endpoint
        :raise NDSSException

        :return dict from response json, status code as integer
        """
        response = self._fetch_ndss(endpoint, 'GET', params_get, data=None)
        if response is not None:
            return response.json(), response.status_code
        return None, None

    def _post_to_ndss(
            self,
            endpoint: str,
            params_get: Dict[str, str],
            data: bytes
    ) -> Tuple[Optional[Dict], Optional[int]]:
        """
        Sends POST-request with data to NDSS endpoint
        :raise NDSSException

        :return dict from response json, status code as integer
        """
        if not isinstance(data, bytes):
            data = b''
        response = self._fetch_ndss(endpoint, 'POST', params_get, data)
        if response is not None:
            return response.json(), response.status_code
        return None, None

    def _fetch_ndss(
            self,
            endpoint: str,
            method: str,
            params_get: Dict[str, str],
            data: Optional[bytes]
    ) -> 'requests.Response':
        """
        Sends GET or POST request to NDSS endpoint
        :raise NDSSException

        :return dict from response json, status code as integer
        """

        params_get['___output'] = 'text/json'

        # if crt file is NOT set, we will verify requests
        verify_request: Union[str, bool] = True
        if self._server_crt_name:
            crt_directory = path.join(path.dirname(__file__), 'crt')
            certificate_file = f'{crt_directory}/{self._server_crt_name}.crt'
            if path.isfile(certificate_file):
                verify_request = certificate_file
            else:
                # however, if crt file is set, but not found locally, we will pass verification
                verify_request = False

        url = f'{self._server_host}/{endpoint}'
        if params_get:
            # to encode?
            pairs = '&'.join([f'{k}={v}' for k, v in params_get.items()])
            url = f'{url}?{pairs}'

        headers = {
            'Authorization': NDSS._get_basic_auth_str(self._auth_login, self._auth_password)
        }

        try:
            if method == 'POST':
                response = \
                    requests.post(url, data, headers=headers, verify=verify_request, timeout=self._server_timeout)
            else:
                response = requests.get(url, headers=headers, verify=verify_request, timeout=self._server_timeout)
            return response
        except Exception as exc:
            # all network and https errors
            raise NDSSException(exc)

    def validate_link(
            self,
            device_ec_public: str,
            service_ec_public: str,
            token_alias: str,
            timestamp: int,
            ec_signature: str
    ) -> None:
        """
        Requests NDSS to perform validateLink operation

        :param device_ec_public: base58-encoded string with device public (verifying) key
        :param service_ec_public: base58-encoded string with service public (verifying) key
        :param token_alias: device token alias
        :param timestamp: timestamp value, used in signature
        :param ec_signature: base58-encoded string with signature (sign_ec_signature_for_validate)

        :raises: NDSSException, KeeneticDeviceException

        (there is no result value, as this method is intended to be called NOT from main thread)
        """
        ndss_info, status = self._post_to_ndss(
            'ndmp/validateLink',
            {
                'intent': 'validateLink',
                'serviceId': self.service_id,
                'deviceEcPublic': device_ec_public,
                'serviceEcPublic': service_ec_public,
                'alias': token_alias,  # please don't ask why alias, not tokenAlias
                'timestamp': timestamp,
                'ecSignature': ec_signature
            },
            b''
        )
        if status != 200:
            ndss_code, ndss_error = self._explain_response(ndss_info)
            raise KeeneticDeviceException(ndss_code, ndss_error)

    def resolve_license(
            self,
            service_tag: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Requests NDSS to resolve Keenetic license (service tag) to token alias and device system name.

        :param service_tag: string, 15 digits

        :return:
        token alias, system name, device hardware identifier (or 3*None if not resolved)
        """
        response_json, status = self._get_from_ndss(
            'ndns/resolveLicense',
            {
                'license': service_tag
            }
        )
        if status == 200:
            if 'values' in response_json:
                vals = response_json.get('values')
                return vals.get('tokenAlias'), vals.get('systemName'), vals.get('ndmHwId')
        return None, None, None

    @staticmethod
    def _generate_ndma_token():
        """
        Generates token to be send to Keenetic device

        :return: string with generated token value
        """
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(32))

    def trust_token(
            self,
            token_alias: str,
            service_ec_private: str,
            service_ec_public: str,
            token_lives_sec: int,
            access_role: Optional[str],
            user_data: Optional[str]
    ) -> Tuple[str, int]:
        """
        Requests NDSS to send access token to Keenetic device.

        Generates access token and sends it to the device with given token_alias.
        If device grants authorization and accepts token, return generated token

        :param token_alias: string with device token alias
        :param service_ec_private: base58-encoded string with private key
        :param service_ec_public: base58-encoded string with public key
        :param token_lives_sec: access duration for token, in seconds
        :param user_data:
        :param access_role:

        :raise: KeeneticDeviceException

        :return: generated and accepted access token string and expiration timestamp, or Nones if failed
        """

        if not access_role:
            access_role = 'owner-admin'
        if not user_data:
            user_data = 'unknown admin'

        ndma_token = NDSS._generate_ndma_token()
        signing_key = load_ec_private(service_ec_private)  # EXException can be raised here

        ec_signature, timestamp, expires_at = \
            sign_ec_signature_for_trust(
                signing_key,
                self.service_id,
                access_role,
                ndma_token,
                token_lives_sec,
                user_data
            )

        response_json, status = self._get_from_ndss(
            'ndmp/trustBearer',
            {
                'alias': token_alias,
                'serviceEcPublic': service_ec_public,
                'intent': 'trustCookie',
                'serviceId': self.service_id,
                'accessRole': access_role,
                'cookieText': ndma_token,
                'expiresAt': expires_at,
                'userData': user_data,
                'timestamp': timestamp,
                'ecSignature': ec_signature
            }
        )
        if status != 200:
            ndss_code, ndss_error = self._explain_response(response_json)
            raise KeeneticDeviceException(ndss_code, ndss_error)
        return ndma_token, expires_at

    @staticmethod
    def _explain_response(response_json: Dict) -> Tuple[str, str]:
        """
        Searches for error code and error explanation in all known NDSS response formats

        :return: string with error code and error description
        """
        message = response_json.get('message')
        if isinstance(message, dict):
            title = message.get('title')
            if isinstance(title, dict) and 'title' in title and 'result' in title:
                return title.get('result'), title.get('title')
            if 'code' in message and 'reason' in message:
                code = message.get('code')
                if code == 414:
                    return '0x414', message.get('reason')
        return '0x101', "unexpected answer format"

    def get_info(
            self,
            token_alias: str,
            bearer_value: str,
            explained: bool = True
    ) -> Optional[Dict[str, object]]:
        """

        :param token_alias: string with token alias
        :param bearer_value: string with bearer token
        :param explained: if true, returns values with explained keys

        :raise: KeeneticDeviceException

        :return: dict with information from remote device
        """
        response_json, status = self._get_from_ndss(
            'ndns/remoteInfo',
            {
                'alias': token_alias,
                'queryV': 1,
                'queryText':
                    f'1000:{bearer_value};'
                    f'2000;2001;2002;2011;2012;2022;2023;'
                    f'3000;3001;3002;'
                    f'4004;4005;4011;4087;'
                    f'5100;5101;5102;5103;5104'
            }
        )
        if status != 200:
            ndss_code, ndss_info = self._explain_response(response_json)
            raise KeeneticDeviceException(ndss_code, ndss_info)

        if 'rows' in response_json and isinstance(response_json.get('rows'), list):
            not_explained_result = {x.get('code'): x.get('text') for x in response_json.get('rows') if x.get('code')}
            if explained:
                explains = {
                    '1000': 'bearer_is_valid',
                    '2000': 'rrst_version',
                    '4004': 'model_name',
                    '5100': 'fw_version'
                }
                # returning only explained values
                return {explains.get(k): v for k, v in not_explained_result.items()}
            return not_explained_result
        return None
