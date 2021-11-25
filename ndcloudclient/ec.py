"""
Elliptic Curve Signing and Verifying Methods
"""

from typing import *
from base58 import b58decode, b58encode
from hashlib import sha256
from datetime import datetime
from ecdsa.keys import SigningKey, VerifyingKey, BadSignatureError, BadDigestError, MalformedPointError
from ecdsa.curves import NIST256p
from ecdsa.util import sigdecode_der, sigencode_der


class ECException(Exception):
    """
    Raises if something was wrong with EC methods
    """
    def __init__(self, description):
        print('EC error: ' + str(description))
        super().__init__()


class VerifySignatureError(Exception):
    """
    Raises from check_signature_from_json and check_signature, in all known cases.
    """
    def __init__(self, description):
        super().__init__(description)


class VerifySignatureOptions(object):
    """
    Options for checking signatures
    """
    skip_check_timestamp: bool = False


def verify_signature_from_dict(
        params: Dict,
        options: VerifySignatureOptions = None
) -> bool:
    """
    Checks, if ec_signature string was really signed by Keenetic device

    :param params: dictionary, with some mandatory keys
    :param options: checking options

    :return: True if verified, or False
    :raise CheckSignatureError
    """
    if not options or not isinstance(options, VerifySignatureOptions):
        options = VerifySignatureOptions()  # default options

    are_all_params, missing_params = _contains_all(
            params, ['serviceId', 'deviceEcPublic', 'timestamp', 'ecSignature'])

    if not are_all_params:
        raise VerifySignatureError('missing mandatory parameters: ' + ', '.join(missing_params))

    timestamp: str = params.get('timestamp')
    try:
        timestamp_request = int(timestamp)
        timestamp_now = _timestamp_now()

        if not options.skip_check_timestamp:
            if abs(timestamp_now - timestamp_request) > 10 * 60:
                raise VerifySignatureError('wrong timestamp value. must be in 10-min interval.')
    except ValueError:
        raise VerifySignatureError('wrong timestamp format')

    return verify_signature(
        params.get('serviceId'),
        timestamp_request,
        params.get('deviceEcPublic'),
        params.get('ecSignature')
    )


def verify_signature(
        service_id: str,
        timestamp: int,
        device_ec_public: str,
        ec_signature: str
) -> bool:
    """
    Checks, if ec_signature string was really signed by Keenetic device

    :param service_id: string with service identifier (from your given config)
    :param timestamp: timestamp values as integer
    :param device_ec_public: base58-encoded string with compressed device public key
    :param ec_signature: base58-encoded string, signed by device private key

    :return: True if verified, or False
    :raise CheckSignatureError
    """

    # Keenetic router constructs string from 3 parameters: service identifier, public key and
    # router current timestamp, hashes string using SHA256 algorithm, and signs result with own **private** key.
    # This hashed and signed string is called ec_signature, we must verify it.

    # We construct the same string here, and **verify** it with router **public** key (device_ec_public).
    checking_string = f'linkService\n{service_id}\n{device_ec_public}\n{str(timestamp)}\n'

    # Decoding device public key from base58-encoded string to compressed format in bytes
    try:
        device_ec_public_bytes: bytes = b58decode(device_ec_public)
    except (ValueError, UnicodeError):
        raise VerifySignatureError('wrong format for device_ec_public, must be base58-encoded')

    # Keenetic uses NIST Curve P-256 algorithm
    try:
        device_verifying_key: 'VerifyingKey' = VerifyingKey.from_string(device_ec_public_bytes, curve=NIST256p)
    except MalformedPointError:
        raise VerifySignatureError('malformed device_ec_public')

    # Decoding signature from base58-encoded string to bytes for verifying
    try:
        ec_signature_bytes: bytes = b58decode(ec_signature)
    except (ValueError, UnicodeError):
        raise VerifySignatureError('wrong format for ec_signature, must be base58-encoded')

    # Verifying signature. Keenetic uses SHA256 algorithm to hash string before signing.
    try:
        # Generally, vk.verify(...) method returns True or raises typed exception,
        # but we return False in case of failed verification.
        return device_verifying_key.verify(
            ec_signature_bytes,
            checking_string.encode('utf-8'),
            hashfunc=sha256, sigdecode=sigdecode_der
        )
    except BadDigestError:
        raise VerifySignatureError('bad digest error. wrong curve type or hashing algorithm?')
    except BadSignatureError:
        return False


def generate_ec_keys() -> 'SigningKey':
    """
    Generates private and public keys.
    SigningKey is a private key, SigningKey.verifying_key is a public key.

    :return: ecdsa.keys.SigningKey
    """
    return SigningKey.generate(curve=NIST256p)


def load_ec_private(
        key_string: str
) -> 'SigningKey':
    """
    Loads Signing key (private) from base58-encoded string
    :param key_string: base58-encoded string

    :raise ECException
    :return: SigningKey
    """
    try:
        return SigningKey.from_string(b58decode(key_string), curve=NIST256p)
    except (ValueError, MalformedPointError, RuntimeError):
        raise ECException("failed to create SigningKey from string")


def get_ec_public_key(verifying_key: 'VerifyingKey') -> str:
    """
    Returns public (verifying) key as base58-encoded string

    :param verifying_key: ecdsa.keys.VerifyingKey (from SigningKey.verifying_key)
    :return: base58-encoded string (of compressed)
    """
    return b58encode(verifying_key.to_string('compressed')).decode('utf-8')


def get_ec_private_key(signing_key: 'SigningKey') -> str:
    """
    Returns private (signing) key as base58-encoded string

    :param signing_key: ecdsa.keys.SigningKey
    :return: base58-encoded string
    """
    return b58encode(signing_key.to_string()).decode('utf-8')


def _sign_ec_signature(
        signing_key: 'SigningKey',
        intent: str,
        params_list: List[str]
) -> str:
    """
    Creates signature of with values from params_list
    Constructs string, hashes and signs, then converts to base58

    :return: base58-encoded string
    """
    string_to_sign = f'{intent}\n' + ''.join([f'{str(x)}\n' for x in params_list])
    signature_bytes = signing_key.sign(string_to_sign.encode('utf-8'), hashfunc=sha256, sigencode=sigencode_der)
    return b58encode(signature_bytes).decode('utf-8')


def sign_ec_signature_for_validate(
        signing_key: 'SigningKey',
        service_id: str,
        device_ec_public: str,
        service_ec_public: str,
) -> Tuple[str, int]:
    """
    Creates signature for validateLink API method.

    Constructs string, hashes and signs, then converts to base58
    This string is intended to be sent during validateLink request

    :return: base58-encoded string, used timestamp value
    """
    timestamp = _timestamp_now()
    signature = _sign_ec_signature(
        signing_key, 'validateLink',
        [service_id, device_ec_public, service_ec_public, timestamp]
    )
    return signature, timestamp


def sign_ec_signature_for_trust(
        signing_key: 'SigningKey',
        service_id: str,
        access_role: str,
        cookie_text: str,
        expires_seconds: int,
        user_data: str
) -> Tuple[str, int, int]:
    """
    Creates signature for trustCookie API method.

    Constructs string, hashes and signs, then converts to base58
    This string is intended to be sent during trustBearer request

    :return: base58-encoded string, used timestamp value, used expiration value
    """
    timestamp = _timestamp_now()
    expires_at = timestamp + expires_seconds
    signature = _sign_ec_signature(
        signing_key, 'trustCookie',
        [service_id, access_role, cookie_text, expires_at, user_data, timestamp]
    )
    return signature, timestamp, expires_at


# Helper functions


def _contains_all(params: Dict[str], mandatory: List[str]) -> Tuple[bool, List[str]]:
    """
    Checks, if given params dict contains all keys from mandatory list

    :param params: dict of strings
    :param mandatory: list of strings
    :return: true if contains all mandatory parameters or false, list of missing mandatory parameters
    """
    keys = params.keys()
    return all(m in keys for m in mandatory), [m for m in mandatory if m not in keys]


def _timestamp_now() -> int:
    """
    Current timestamp, seconds since 1970-01-01
    """
    return int(datetime.now().timestamp())
