"""
Author: dhaneshwar
Custom CyberArk Privilege Cloud connector for FortiSOAR.

CyberArk Privilege Cloud - FortiSOAR Connector Operations

Supports BOTH deployment types:

  1. ISPSS (Identity Security Platform Shared Services) - *.cyberark.cloud
     Auth via CyberArk Identity:
       - Service User: POST https://<tenant>.id.cyberark.cloud/oauth2/platformtoken
       - Interactive User: POST /Security/StartAuthentication + /Security/AdvanceAuthentication
     API base: https://<tenant>.privilegecloud.cyberark.cloud/PasswordVault/API/

  2. Privilege Cloud Standard - *.privilegecloud.cyberark.com
     Auth via: POST /PasswordVault/API/auth/{CyberArk|LDAP|RADIUS}/Logon/
     API base: https://<subdomain>.privilegecloud.cyberark.com/PasswordVault/API/

References:
  https://docs.cyberark.com/privilege-cloud-standard/latest/en/content/webservices/
  https://docs.cyberark.com/ispss-deployment/latest/en/Content/ISPSS/ISPSS-API-Authentication.htm
  https://docs.cyberark.com/identity-administration/Latest/en/Content/Developer/authentication/start-auth-process.htm
"""

import json
import time
import re
import requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('cyberark-privilege-cloud-ispss')

SUCCESS_CODES = [200, 201, 204]
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds


def _extract_subdomain(url):
    """
    Extract the tenant subdomain from a CyberArk URL.

    Handles:
      https://acme.cyberark.cloud           -> acme
      https://acme.privilegecloud.cyberark.cloud -> acme
      https://acme.privilegecloud.cyberark.com   -> acme
      https://acme.id.cyberark.cloud        -> acme
    """
    url = url.strip().rstrip('/')
    if not url.startswith('https://'):
        url = 'https://' + url
    host = url.split('://')[1].split('/')[0]
    return host.split('.')[0]


def _detect_platform(url):
    """
    Detect whether the URL is ISPSS or Privilege Cloud Standard.

    Returns: 'ispss' or 'standard'
    """
    url_lower = url.lower()
    # *.cyberark.cloud (without 'privilegecloud' in it) = ISPSS portal
    # *.privilegecloud.cyberark.cloud = ISPSS PasswordVault API
    # *.privilegecloud.cyberark.com = Standard
    if '.cyberark.cloud' in url_lower:
        return 'ispss'
    elif '.privilegecloud.cyberark.com' in url_lower:
        return 'standard'
    else:
        # Unknown format - assume standard (on-prem style URL)
        return 'standard'


class PrivilegeCloudClient:
    """
    HTTP client for CyberArk Privilege Cloud REST API.

    Auto-detects ISPSS vs Standard based on the server URL and uses
    the appropriate authentication flow.
    """

    # All PasswordVault API endpoints (same for both platforms)
    ENDPOINTS = {
        # Accounts
        'accounts': '/PasswordVault/API/Accounts',
        'account_by_id': '/PasswordVault/API/Accounts/{account_id}',
        'account_password': '/PasswordVault/API/Accounts/{account_id}/Password/Retrieve',
        'account_reconcile': '/PasswordVault/API/Accounts/{account_id}/Reconcile/',

        # Safes
        'safes': '/PasswordVault/API/Safes',
        'safe_by_id': '/PasswordVault/API/Safes/{safe_url_id}',

        # Safe Members
        'safe_members': '/PasswordVault/API/Safes/{safe_url_id}/Members',
        'safe_member': '/PasswordVault/API/Safes/{safe_url_id}/Members/{member_name}/',

        # Account Groups
        'safe_account_groups': '/PasswordVault/API/Safes/{safe_name}/AccountGroups',
        'account_group_members': '/PasswordVault/API/AccountGroups/{group_id}/Members',
        'account_group_member': '/PasswordVault/API/AccountGroups/{group_id}/Members/{account_id}',

        # Users
        'users': '/PasswordVault/API/Users',
        'user_by_id': '/PasswordVault/API/Users/{user_id}',
        'user_reset_password': '/PasswordVault/API/Users/{user_id}/ResetPassword',
        'user_activate': '/PasswordVault/API/Users/{user_id}/Activate',

        # Groups
        'groups': '/PasswordVault/API/UserGroups',
        'group_members': '/PasswordVault/API/UserGroups/{group_id}/Members',

        # Recordings
        'recordings': '/PasswordVault/API/Recordings',
        'recording_by_id': '/PasswordVault/API/Recordings/{recording_id}',
        'recording_play': '/PasswordVault/API/Recordings/{recording_id}/Play',

        # Standard-only auth endpoints
        'logon_standard': '/PasswordVault/API/auth/{auth_type}/Logon/',
        'logoff_standard': '/PasswordVault/API/Auth/Logoff/',
    }

    ERROR_MESSAGES = {
        400: 'Bad/Invalid Request',
        401: 'Unauthorized - Invalid or expired credentials',
        403: 'Forbidden - Insufficient permissions',
        404: 'Not Found - Resource does not exist',
        409: 'Conflict - Resource state conflict',
        429: 'Too Many Requests - API throttled',
        500: 'Internal Server Error',
        501: 'Not Implemented',
        503: 'Service Unavailable',
    }

    def __init__(self, config):
        raw_url = config['server_url'].strip().rstrip('/')
        if not raw_url.startswith('https://'):
            raw_url = 'https://{0}'.format(raw_url)

        self.platform = _detect_platform(raw_url)
        self.subdomain = _extract_subdomain(raw_url)
        self.username = config.get('username')
        self.password = config.get('password')
        self.auth_type = config.get('auth_type', 'CyberArk')
        self.concurrent_session = config.get('concurrent_session', True)
        self.verify_ssl = config.get('verify_ssl', True)
        self.headers = {'Content-Type': 'application/json'}
        self._token = None

        if self.platform == 'ispss':
            # ISPSS: Identity URL and PasswordVault API URL are different hosts.
            # The Identity tenant ID is frequently NOT the portal subdomain, so
            # allow explicit overrides; fall back to the subdomain-derived guess.
            identity_override = (config.get('identity_url') or '').strip().rstrip('/')
            api_override = (config.get('api_url') or '').strip().rstrip('/')
            self.identity_url = identity_override if identity_override \
                else 'https://{0}.id.cyberark.cloud'.format(self.subdomain)
            self.base_url = api_override if api_override \
                else 'https://{0}.privilegecloud.cyberark.cloud'.format(self.subdomain)
            logger.info('Detected ISPSS platform. Identity: {0}, API: {1}'.format(
                self.identity_url, self.base_url))
        else:
            # Standard: everything is on the same host
            self.identity_url = None
            self.base_url = raw_url
            logger.info('Detected Privilege Cloud Standard. API: {0}'.format(self.base_url))

    def _build_url(self, endpoint_key, **kwargs):
        """Build full URL from endpoint template and parameters."""
        endpoint = self.ENDPOINTS[endpoint_key].format(**kwargs)
        return '{base}{endpoint}'.format(base=self.base_url, endpoint=endpoint)

    def _raw_request(self, method, url, payload=None, query_params=None, headers=None,
                     expect_json=True):
        """Low-level HTTP request without retry logic. Used by auth flows."""
        use_headers = headers if headers else self.headers
        try:
            response = requests.request(
                method,
                url,
                data=json.dumps(payload) if payload else None,
                params=query_params,
                headers=use_headers,
                verify=self.verify_ssl,
                timeout=120
            )
            return response
        except requests.exceptions.SSLError as e:
            logger.exception(e)
            raise ConnectorError('SSL certificate validation failed: {0}'.format(e))
        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
            raise ConnectorError('Connection error - unable to reach server: {0}'.format(e))
        except requests.exceptions.Timeout as e:
            logger.exception(e)
            raise ConnectorError('Request timed out: {0}'.format(e))
        except Exception as e:
            logger.exception(e)
            raise ConnectorError('Request error: {0}'.format(e))

    def _request(self, method, url, payload=None, query_params=None, retry_on_429=True):
        """
        Execute HTTP request with retry logic for 429 (API throttling).

        CyberArk Privilege Cloud throttles API requests when the queue time is too long.
        Per the official docs, we retry after a short interval on 429 responses.
        """
        attempt = 0
        while attempt <= MAX_RETRIES:
            response = self._raw_request(method, url, payload=payload,
                                         query_params=query_params)

            if response.status_code in SUCCESS_CODES:
                if response.status_code == 204:
                    return None
                content_type = response.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    return response.json()
                # Some endpoints return a bare string (e.g. password retrieve)
                text = response.text.strip().strip('"')
                if text:
                    return text
                return None

            if response.status_code == 429 and retry_on_429 and attempt < MAX_RETRIES:
                attempt += 1
                wait = RETRY_DELAY * attempt
                logger.warning('API throttled (429). Retry {0}/{1} after {2}s'.format(
                    attempt, MAX_RETRIES, wait))
                time.sleep(wait)
                continue

            # Error handling
            error_detail = self.ERROR_MESSAGES.get(response.status_code,
                                                   'HTTP {0}'.format(response.status_code))
            try:
                err_body = response.json()
                if isinstance(err_body, dict):
                    error_detail = err_body.get('ErrorMessage',
                                  err_body.get('Details',
                                  err_body.get('Message', error_detail)))
            except Exception:
                # If response is HTML (like IWA redirect), give a clear message
                if '<html' in response.text[:200].lower():
                    error_detail = ('Server returned HTML instead of JSON. '
                                    'This usually means the URL is wrong or '
                                    'authentication redirect is occurring. '
                                    'Status: {0}'.format(response.status_code))
                pass

            raise ConnectorError('{0}: {1}'.format(response.status_code, error_detail))

        raise ConnectorError('Max retries ({0}) exceeded due to API throttling'.format(MAX_RETRIES))

    def _request_bytes(self, method, url, payload=None, query_params=None, retry_on_429=True):
        """
        Execute an HTTP request and return the RAW response bytes.

        Used for endpoints that return a binary file (e.g. a PSM session
        recording). Unlike _request, this never decodes the body to text -
        text-decoding binary corrupts it (valid bytes turn into U+FFFD) and
        bloats the payload. Keeps the same 429 throttling retry behaviour.

        Returns: (content_bytes, content_type)
        """
        attempt = 0
        while attempt <= MAX_RETRIES:
            response = self._raw_request(method, url, payload=payload,
                                         query_params=query_params)

            if response.status_code in SUCCESS_CODES:
                if response.status_code == 204:
                    return b'', ''
                return response.content, response.headers.get('Content-Type', '')

            if response.status_code == 429 and retry_on_429 and attempt < MAX_RETRIES:
                attempt += 1
                wait = RETRY_DELAY * attempt
                logger.warning('API throttled (429). Retry {0}/{1} after {2}s'.format(
                    attempt, MAX_RETRIES, wait))
                time.sleep(wait)
                continue

            error_detail = self.ERROR_MESSAGES.get(response.status_code,
                                                   'HTTP {0}'.format(response.status_code))
            try:
                err_body = response.json()
                if isinstance(err_body, dict):
                    error_detail = err_body.get('ErrorMessage',
                                  err_body.get('Details',
                                  err_body.get('Message', error_detail)))
            except Exception:
                if '<html' in response.text[:200].lower():
                    error_detail = ('Server returned HTML instead of the recording file. '
                                    'This usually means the URL is wrong or an '
                                    'authentication redirect is occurring. '
                                    'Status: {0}'.format(response.status_code))

            raise ConnectorError('{0}: {1}'.format(response.status_code, error_detail))

        raise ConnectorError('Max retries ({0}) exceeded due to API throttling'.format(MAX_RETRIES))

    # ================================================================
    # ISPSS Authentication via CyberArk Identity
    # ================================================================

    def _login_ispss_identity(self):
        """
        Authenticate to CyberArk Identity using StartAuthentication + AdvanceAuthentication.

        Flow:
          1. POST /Security/StartAuthentication  -> get SessionId, Challenges, MechanismId
          2. Find the 'UP' (username/password) mechanism
          3. POST /Security/AdvanceAuthentication -> answer with password
          4. On LoginSuccess, extract the Auth token
          5. Use token as Bearer in Authorization header for PasswordVault API calls

        Reference:
          https://docs.cyberark.com/identity-administration/Latest/en/Content/Developer/authentication/start-auth-process.htm
        """
        identity_headers = {
            'Content-Type': 'application/json',
            'X-IDAP-NATIVE-CLIENT': 'true',
        }

        # Step 1: StartAuthentication
        start_url = '{0}/Security/StartAuthentication'.format(self.identity_url)
        start_payload = {
            'User': self.username,
            'Version': '1.0',
        }

        logger.info('ISPSS: Starting authentication for user {0} at {1}'.format(
            self.username, self.identity_url))

        resp = self._raw_request('POST', start_url, payload=start_payload,
                                 headers=identity_headers)

        if resp.status_code != 200:
            raise ConnectorError(
                'ISPSS StartAuthentication failed (HTTP {0}): {1}'.format(
                    resp.status_code, resp.text[:500]))

        start_result = resp.json()

        if not start_result.get('success'):
            error_msg = start_result.get('Message') or start_result.get('Exception') or 'Unknown error'
            raise ConnectorError('ISPSS StartAuthentication failed: {0}'.format(error_msg))

        result = start_result.get('Result', {})
        session_id = result.get('SessionId')
        tenant_id = result.get('TenantId')
        challenges = result.get('Challenges', [])
        summary = result.get('Summary', '')

        if not session_id:
            raise ConnectorError('ISPSS StartAuthentication returned no SessionId')

        if summary == 'LoginSuccess':
            # No challenges needed (unlikely but handle it)
            token = result.get('Auth')
            if token:
                self._token = token
                self.headers['Authorization'] = 'Bearer {0}'.format(self._token)
                logger.info('ISPSS: Authenticated (no challenges required)')
                return
            raise ConnectorError('ISPSS: LoginSuccess but no Auth token in response')

        if not challenges:
            raise ConnectorError(
                'ISPSS: No authentication challenges returned. '
                'Summary: {0}. The user may not have an authentication policy configured.'.format(summary))

        # Step 2: Find the UP (Username/Password) mechanism in the first challenge
        up_mechanism_id = None
        for challenge in challenges:
            for mechanism in challenge.get('Mechanisms', []):
                if mechanism.get('Name') == 'UP':
                    up_mechanism_id = mechanism.get('MechanismId')
                    break
            if up_mechanism_id:
                break

        if not up_mechanism_id:
            # List what mechanisms ARE available for better debugging
            available = []
            for challenge in challenges:
                for mechanism in challenge.get('Mechanisms', []):
                    available.append(mechanism.get('Name', 'unknown'))
            raise ConnectorError(
                'ISPSS: No password (UP) mechanism found in challenges. '
                'Available mechanisms: {0}. '
                'Your user may require MFA which is not supported for headless API automation. '
                'Ask your CyberArk Identity admin to create a Service User instead.'.format(
                    ', '.join(available)))

        # Step 3: AdvanceAuthentication - answer the UP challenge with the password
        advance_url = '{0}/Security/AdvanceAuthentication'.format(self.identity_url)
        advance_payload = {
            'SessionId': session_id,
            'MechanismId': up_mechanism_id,
            'Action': 'Answer',
            'Answer': self.password,
        }
        if tenant_id:
            advance_payload['TenantId'] = tenant_id

        resp = self._raw_request('POST', advance_url, payload=advance_payload,
                                 headers=identity_headers)

        if resp.status_code != 200:
            raise ConnectorError(
                'ISPSS AdvanceAuthentication failed (HTTP {0}): {1}'.format(
                    resp.status_code, resp.text[:500]))

        advance_result = resp.json()

        if not advance_result.get('success'):
            error_msg = advance_result.get('Message') or advance_result.get('Exception') or 'Unknown error'
            raise ConnectorError('ISPSS AdvanceAuthentication failed: {0}'.format(error_msg))

        adv_result = advance_result.get('Result', {})
        adv_summary = adv_result.get('Summary', '')

        if adv_summary == 'LoginSuccess':
            # Extract the auth token
            token = adv_result.get('Auth')
            if not token:
                # Sometimes the token comes in the response cookies
                token = resp.cookies.get('.ASPXAUTH')

            if not token:
                # Try extracting from Token field
                token = adv_result.get('Token')

            if not token:
                raise ConnectorError(
                    'ISPSS: LoginSuccess but no Auth token found in response. '
                    'Keys in result: {0}'.format(list(adv_result.keys())))

            self._token = token
            self.headers['Authorization'] = 'Bearer {0}'.format(self._token)
            logger.info('ISPSS: Successfully authenticated as {0}'.format(self.username))
            return

        elif adv_summary == 'StartNextChallenge':
            # MFA is required - second challenge
            raise ConnectorError(
                'ISPSS: MFA is required (StartNextChallenge). '
                'Headless API automation cannot complete MFA challenges. '
                'Ask your CyberArk Identity admin to either: '
                '(1) Create a Service User with client_credentials grant, or '
                '(2) Exempt your API user from MFA in the authentication policy.')

        elif adv_summary == 'OobPending':
            raise ConnectorError(
                'ISPSS: Out-of-band MFA verification pending (OobPending). '
                'This cannot be completed in headless automation. '
                'Ask your CyberArk Identity admin to create a Service User.')

        else:
            raise ConnectorError(
                'ISPSS: Unexpected AdvanceAuthentication summary: {0}. '
                'Full result: {1}'.format(adv_summary, json.dumps(adv_result)[:500]))

    def _login_ispss_service_user(self):
        """
        Authenticate using OAuth2 client_credentials grant for ISPSS Service Users.

        Endpoint: POST https://<tenant>.id.cyberark.cloud/oauth2/platformtoken
        Body (form-encoded): grant_type=client_credentials&client_id=...&client_secret=...

        Reference:
          https://docs.cyberark.com/ispss-deployment/latest/en/Content/ISPSS/ISPSS-API-Authentication.htm
        """
        token_url = '{0}/oauth2/platformtoken'.format(self.identity_url)
        token_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        token_data = 'grant_type=client_credentials&client_id={0}&client_secret={1}'.format(
            requests.utils.quote(self.username),
            requests.utils.quote(self.password),
        )

        logger.info('ISPSS: Authenticating service user via platformtoken')

        resp = requests.post(
            token_url,
            data=token_data,
            headers=token_headers,
            verify=self.verify_ssl,
            timeout=60
        )

        if resp.status_code != 200:
            raise ConnectorError(
                'ISPSS OAuth2 token request failed (HTTP {0}): {1}'.format(
                    resp.status_code, resp.text[:500]))

        token_resp = resp.json()
        access_token = token_resp.get('access_token')

        if not access_token:
            raise ConnectorError('ISPSS OAuth2: No access_token in response')

        self._token = access_token
        self.headers['Authorization'] = 'Bearer {0}'.format(self._token)
        logger.info('ISPSS: Service user authenticated successfully')

    # ================================================================
    # Standard Authentication (Privilege Cloud Standard)
    # ================================================================

    def _login_standard(self):
        """
        Authenticate to Privilege Cloud Standard.

        Endpoint: POST /PasswordVault/API/auth/{CyberArk|LDAP|RADIUS}/Logon/
        Body: {"username": "...", "password": "...", "concurrentSession": true/false}
        Returns: Session token string (bare JSON string).
        """
        endpoint = self.ENDPOINTS['logon_standard'].format(auth_type=self.auth_type)
        url = '{base}{endpoint}'.format(base=self.base_url, endpoint=endpoint)
        payload = {
            'username': self.username,
            'password': self.password,
            'concurrentSession': self.concurrent_session
        }

        resp = self._raw_request('POST', url, payload=payload)

        if resp.status_code not in SUCCESS_CODES:
            # Check if we got HTML back (IWA redirect = wrong platform)
            if '<html' in resp.text[:200].lower():
                raise ConnectorError(
                    'Authentication returned an HTML page instead of a token. '
                    'This typically means your tenant is ISPSS (*.cyberark.cloud) '
                    'not Privilege Cloud Standard. The connector detected "standard" '
                    'from your URL but the server is redirecting to Identity/IWA. '
                    'Check your Server URL configuration.')
            raise ConnectorError('Standard auth failed (HTTP {0}): {1}'.format(
                resp.status_code, resp.text[:500]))

        content_type = resp.headers.get('Content-Type', '')
        if 'application/json' in content_type:
            token = resp.json()
        else:
            token = resp.text.strip().strip('"')

        if not token or (isinstance(token, str) and '<html' in token.lower()):
            raise ConnectorError(
                'Authentication failed - server returned HTML instead of token. '
                'Your tenant may be ISPSS. Use the *.cyberark.cloud portal URL.')

        self._token = token if isinstance(token, str) else str(token)
        self.headers['Authorization'] = self._token
        logger.info('Standard: Authenticated as {0} via {1}'.format(
            self.username, self.auth_type))

    # ================================================================
    # Unified Login/Logout
    # ================================================================

    def login(self):
        """Authenticate using the appropriate method based on platform detection."""
        if self.platform == 'ispss':
            if self.auth_type == 'ServiceUser':
                self._login_ispss_service_user()
            else:
                self._login_ispss_identity()
        else:
            self._login_standard()

    def logout(self):
        """Logoff and invalidate the session token."""
        try:
            if self._token and self.platform == 'standard':
                # Standard has an explicit logoff endpoint
                endpoint = self.ENDPOINTS['logoff_standard']
                url = '{base}{endpoint}'.format(base=self.base_url, endpoint=endpoint)
                self._raw_request('POST', url)
            # ISPSS tokens expire naturally; no explicit logoff needed
        except Exception as e:
            logger.warning('Logoff failed (non-critical): {0}'.format(e))
        finally:
            self._token = None
            self.headers.pop('Authorization', None)

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()
        return False


# ============================================================
# Helper
# ============================================================

def _clean_params(params_dict):
    """Remove None and empty-string values from a dict."""
    return {k: v for k, v in params_dict.items() if v is not None and v != ''}


# ============================================================
# Health Check
# ============================================================

def _check_health(config):
    """Verify connectivity and authentication to Privilege Cloud."""
    try:
        client = PrivilegeCloudClient(config)
        client.login()
        vault = config.get('vault', False)
        if vault:
            vault_safe = config.get('vault_safe')
            if not vault_safe:
                raise ConnectorError('Vault mode enabled but no Safe Name configured')
            url = client._build_url('accounts')
            query = {'filter': 'safeName eq {0}'.format(vault_safe), 'limit': 1}
            result = client._request('GET', url, query_params=query)
            if not result or result.get('count', 0) == 0:
                logger.warning('Vault safe "{0}" returned 0 accounts - verify safe name and permissions'.format(
                    vault_safe))
        client.logout()
        return True
    except Exception as err:
        logger.exception('Health check failed: {0}'.format(err))
        raise ConnectorError('Health check failed: {0}'.format(err))


# ============================================================
# Account Operations
# ============================================================

def get_account(config, params):
    """
    GET /PasswordVault/API/Accounts?search=...&filter=...&limit=...&offset=...
    """
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('accounts')
        query = _clean_params({
            'search': params.get('search'),
            'searchType': params.get('searchType'),
            'filter': params.get('filter'),
            'savedfilter': params.get('savedfilter'),
            'sort': params.get('sort'),
            'offset': params.get('offset'),
            'limit': params.get('limit'),
        })
        return client._request('GET', url, query_params=query)


def get_account_details(config, params):
    """
    GET /PasswordVault/API/Accounts/{AccountId}
    """
    account_id = params.get('account_id')
    if not account_id:
        raise ConnectorError('account_id is required')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('account_by_id', account_id=account_id)
        return client._request('GET', url)


def retrieve_account_password(config, params):
    """
    POST /PasswordVault/API/Accounts/{AccountId}/Password/Retrieve

    Retrieves the password or SSH key of an existing account.
    Requires 'Retrieve Accounts' permission on the Safe.
    """
    account_id = params.get('account_id')
    if not account_id:
        raise ConnectorError('account_id is required')

    body = _clean_params({
        'reason': params.get('reason'),
        'TicketingSystemName': params.get('TicketingSystemName'),
        'TicketId': params.get('TicketId'),
        'ActionType': params.get('ActionType'),
        'isUse': params.get('isUse'),
    })

    with PrivilegeCloudClient(config) as client:
        url = client._build_url('account_password', account_id=account_id)
        password = client._request('POST', url, payload=body if body else None)
        return {'password': password}


def reconcile_credentials(config, params):
    """
    POST /PasswordVault/API/Accounts/{AccountId}/Reconcile/
    """
    account_id = params.get('account_id')
    if not account_id:
        raise ConnectorError('account_id is required')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('account_reconcile', account_id=account_id)
        result = client._request('POST', url)
        return result or {'message': 'Reconciliation initiated successfully'}


# ============================================================
# Safe Operations
# ============================================================

def add_safe(config, params):
    """
    POST /PasswordVault/API/Safes
    """
    description = params.get('description', '')
    if description and len(description) > 100:
        raise ConnectorError('Description must not exceed 100 characters')

    body = _clean_params({
        'safeName': params.get('safeName'),
        'description': description,
        'managingCPM': params.get('managingCPM'),
        'numberOfDaysRetention': params.get('numberOfDaysRetention'),
        'numberOfVersionsRetention': params.get('numberOfVersionsRetention'),
        'OLACEnabled': params.get('OLACEnabled'),
    })

    with PrivilegeCloudClient(config) as client:
        url = client._build_url('safes')
        return client._request('POST', url, payload=body)


def list_safes(config, params):
    """
    GET /PasswordVault/API/Safes?search=...&offset=...&limit=...
    """
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('safes')
        query = _clean_params({
            'search': params.get('search'),
            'offset': params.get('offset'),
            'limit': params.get('limit'),
        })
        return client._request('GET', url, query_params=query)


def get_safe_details(config, params):
    """
    GET /PasswordVault/API/Safes/{SafeUrlId}
    """
    safe_url_id = params.get('safeUrlId')
    if not safe_url_id:
        raise ConnectorError('safeUrlId is required')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('safe_by_id', safe_url_id=safe_url_id)
        return client._request('GET', url)


def update_safe(config, params):
    """
    PUT /PasswordVault/API/Safes/{SafeUrlId}
    """
    safe_url_id = params.get('safeUrlId')
    if not safe_url_id:
        raise ConnectorError('safeUrlId is required')

    body = _clean_params({
        'safeName': params.get('safeName'),
        'description': params.get('description'),
        'managingCPM': params.get('managingCPM'),
        'numberOfDaysRetention': params.get('numberOfDaysRetention'),
        'numberOfVersionsRetention': params.get('numberOfVersionsRetention'),
        'OLACEnabled': params.get('OLACEnabled'),
    })

    with PrivilegeCloudClient(config) as client:
        url = client._build_url('safe_by_id', safe_url_id=safe_url_id)
        return client._request('PUT', url, payload=body)


def delete_safe(config, params):
    """
    DELETE /PasswordVault/API/Safes/{SafeUrlId}
    """
    safe_url_id = params.get('safeUrlId')
    if not safe_url_id:
        raise ConnectorError('safeUrlId is required')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('safe_by_id', safe_url_id=safe_url_id)
        client._request('DELETE', url)
        return {'message': 'Safe "{0}" deleted successfully'.format(safe_url_id)}


# ============================================================
# Safe Member Operations
# ============================================================

def add_safe_member(config, params):
    """
    POST /PasswordVault/API/Safes/{SafeUrlId}/Members
    """
    safe_url_id = params.get('safeUrlId')
    if not safe_url_id:
        raise ConnectorError('safeUrlId is required')

    permissions = params.get('permissions', {})
    if isinstance(permissions, str):
        try:
            permissions = json.loads(permissions)
        except json.JSONDecodeError:
            raise ConnectorError('permissions must be a valid JSON object')

    body = {
        'memberName': params.get('memberName'),
        'permissions': permissions,
    }
    member_type = params.get('memberType')
    if member_type:
        body['memberType'] = member_type

    with PrivilegeCloudClient(config) as client:
        url = client._build_url('safe_members', safe_url_id=safe_url_id)
        return client._request('POST', url, payload=body)


def list_safe_members(config, params):
    """
    GET /PasswordVault/API/Safes/{SafeUrlId}/Members
    """
    safe_url_id = params.get('safeUrlId')
    if not safe_url_id:
        raise ConnectorError('safeUrlId is required')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('safe_members', safe_url_id=safe_url_id)
        return client._request('GET', url)


def update_safe_member(config, params):
    """
    PUT /PasswordVault/API/Safes/{SafeUrlId}/Members/{MemberName}/
    """
    safe_url_id = params.get('safeUrlId')
    member_name = params.get('memberName')
    if not safe_url_id or not member_name:
        raise ConnectorError('safeUrlId and memberName are required')

    permissions = params.get('permissions', {})
    if isinstance(permissions, str):
        try:
            permissions = json.loads(permissions)
        except json.JSONDecodeError:
            raise ConnectorError('permissions must be a valid JSON object')

    body = {'permissions': permissions}

    with PrivilegeCloudClient(config) as client:
        url = client._build_url('safe_member', safe_url_id=safe_url_id, member_name=member_name)
        return client._request('PUT', url, payload=body)


def delete_safe_member(config, params):
    """
    DELETE /PasswordVault/API/Safes/{SafeUrlId}/Members/{MemberName}/
    """
    safe_url_id = params.get('safeUrlId')
    member_name = params.get('memberName')
    if not safe_url_id or not member_name:
        raise ConnectorError('safeUrlId and memberName are required')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('safe_member', safe_url_id=safe_url_id, member_name=member_name)
        client._request('DELETE', url)
        return {'message': 'Member "{0}" removed from safe "{1}"'.format(member_name, safe_url_id)}


# ============================================================
# Account Group Operations
# ============================================================

def get_safe_account_groups(config, params):
    """
    GET /PasswordVault/API/Safes/{SafeName}/AccountGroups
    """
    safe_name = params.get('safeName')
    if not safe_name:
        raise ConnectorError('safeName is required')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('safe_account_groups', safe_name=safe_name)
        return client._request('GET', url)


def add_account_group_member(config, params):
    """
    POST /PasswordVault/API/AccountGroups/{GroupId}/Members
    """
    group_id = params.get('GroupID')
    account_id = params.get('AccountID')
    if not group_id or not account_id:
        raise ConnectorError('GroupID and AccountID are required')
    body = {'AccountID': account_id}
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('account_group_members', group_id=group_id)
        return client._request('POST', url, payload=body)


def get_account_group_members(config, params):
    """
    GET /PasswordVault/API/AccountGroups/{GroupId}/Members
    """
    group_id = str(params.get('GroupID'))
    if not group_id:
        raise ConnectorError('GroupID is required')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('account_group_members', group_id=group_id)
        return client._request('GET', url)


def delete_account_group_member(config, params):
    """
    DELETE /PasswordVault/API/AccountGroups/{GroupId}/Members/{AccountId}
    """
    group_id = str(params.get('GroupID'))
    account_id = str(params.get('AccountID'))
    if not group_id or not account_id:
        raise ConnectorError('GroupID and AccountID are required')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('account_group_member', group_id=group_id, account_id=account_id)
        client._request('DELETE', url)
        return {'message': 'Account "{0}" removed from group "{1}"'.format(account_id, group_id)}


# ============================================================
# User Operations
# ============================================================

def add_user(config, params):
    """
    POST /PasswordVault/API/Users
    """
    body = _clean_params({
        'username': params.get('username'),
        'initialPassword': params.get('initialPassword'),
        'enableUser': params.get('enableUser', True),
        'changePassOnNextLogon': params.get('changePassOnNextLogon', False),
        'vaultAuthorization': params.get('vaultAuthorization'),
        'personalDetails': _clean_params({
            'firstName': params.get('firstName'),
            'lastName': params.get('lastName'),
        }),
        'internet': _clean_params({
            'homeEmail': params.get('email'),
        }),
    })
    # Remove empty nested dicts
    for key in ['personalDetails', 'internet']:
        if key in body and not body[key]:
            del body[key]

    with PrivilegeCloudClient(config) as client:
        url = client._build_url('users')
        return client._request('POST', url, payload=body)


def get_users(config, params):
    """
    GET /PasswordVault/API/Users?search=...&userType=...&componentUser=...
    """
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('users')
        query = _clean_params({
            'search': params.get('search'),
            'userType': params.get('userType'),
            'componentUser': params.get('componentUser'),
        })
        return client._request('GET', url, query_params=query)


def get_user_details(config, params):
    """
    GET /PasswordVault/API/Users/{UserId}
    """
    user_id = params.get('userID')
    if not user_id or user_id < 1:
        raise ConnectorError('userID must be a positive integer')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('user_by_id', user_id=user_id)
        return client._request('GET', url)


def update_user(config, params):
    """
    PUT /PasswordVault/API/Users/{UserId}
    """
    user_id = params.get('userID')
    if not user_id or user_id < 1:
        raise ConnectorError('userID must be a positive integer')

    body = _clean_params({
        'enableUser': params.get('enableUser'),
        'changePassOnNextLogon': params.get('changePassOnNextLogon'),
        'personalDetails': _clean_params({
            'firstName': params.get('firstName'),
            'lastName': params.get('lastName'),
        }),
    })
    if 'personalDetails' in body and not body['personalDetails']:
        del body['personalDetails']

    with PrivilegeCloudClient(config) as client:
        url = client._build_url('user_by_id', user_id=user_id)
        return client._request('PUT', url, payload=body)


def delete_user(config, params):
    """
    DELETE /PasswordVault/API/Users/{UserId}
    """
    user_id = params.get('userID')
    if not user_id or user_id < 1:
        raise ConnectorError('userID must be a positive integer')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('user_by_id', user_id=user_id)
        client._request('DELETE', url)
        return {'message': 'User {0} deleted'.format(user_id)}


def reset_user_password(config, params):
    """
    POST /PasswordVault/API/Users/{UserId}/ResetPassword
    """
    user_id = params.get('userID')
    if not user_id or user_id < 1:
        raise ConnectorError('userID must be a positive integer')
    body = {'newPassword': params.get('newPassword')}
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('user_reset_password', user_id=user_id)
        client._request('POST', url, payload=body)
        return {'message': 'Password reset successful for user {0}'.format(user_id)}


def activate_user(config, params):
    """
    POST /PasswordVault/API/Users/{UserId}/Activate
    """
    user_id = params.get('userID')
    if not user_id or user_id < 1:
        raise ConnectorError('userID must be a positive integer')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('user_activate', user_id=user_id)
        client._request('POST', url)
        return {'message': 'User {0} activated'.format(user_id)}


def add_user_to_group(config, params):
    """
    POST /PasswordVault/API/UserGroups/{GroupId}/Members
    """
    group_id = params.get('groupId')
    member_id = params.get('memberId')
    if not group_id or not member_id:
        raise ConnectorError('groupId and memberId are required')
    body = {'memberId': member_id, 'memberType': 'Vault'}
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('group_members', group_id=group_id)
        return client._request('POST', url, payload=body)


def get_groups(config, params):
    """
    GET /PasswordVault/API/UserGroups?search=...
    """
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('groups')
        query = _clean_params({
            'search': params.get('search'),
        })
        return client._request('GET', url, query_params=query)


# ============================================================
# Recording Operations
# ============================================================

def get_recordings(config, params):
    """
    GET /PasswordVault/API/Recordings?limit=...&offset=...&safe=...&fromTime=...&toTime=...
    """
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('recordings')
        query = _clean_params({
            'limit': params.get('limit'),
            'offset': params.get('offset'),
            'safe': params.get('safe'),
            'fromTime': params.get('fromTime'),
            'toTime': params.get('toTime'),
            'search': params.get('search'),
        })
        return client._request('GET', url, query_params=query)


def get_recording_details(config, params):
    """
    GET /PasswordVault/API/Recordings/{RecordingId}
    """
    recording_id = params.get('recording_id')
    if not recording_id:
        raise ConnectorError('recording_id is required')
    with PrivilegeCloudClient(config) as client:
        url = client._build_url('recording_by_id', recording_id=recording_id)
        return client._request('GET', url)


def _recording_extension(content, content_type):
    """Pick a file extension from the content-type, falling back to the magic bytes."""
    ct = (content_type or '').lower()
    if 'avi' in ct or 'msvideo' in ct:
        return '.avi'
    if 'mp4' in ct or 'mpeg' in ct:
        return '.mp4'
    if 'webm' in ct:
        return '.webm'
    if content[:4] == b'RIFF':          # RIFF/AVI container (CyberArk SCPR)
        return '.avi'
    if content[4:8] == b'ftyp':         # ISO base media (mp4)
        return '.mp4'
    return '.session'


def _save_recording_as_file(file_name, content, content_type):
    """
    Store the recording bytes as a FortiSOAR ATTACHMENT and return its metadata
    (attachment IRI + file IRI), so the recording shows up as a normal
    downloadable attachment on the alert/record - the same way a FortiSOAR
    playbook attaches a report PDF.

    Uses upload_file_to_cyops(file_path=..., create_attachment=True), the
    signature FortiSOAR exposes to connectors (stage the bytes to a file first,
    then hand the path to the platform). Imported lazily and guarded so
    operations.py still loads and runs outside FortiSOAR, where the caller
    falls back to base64.

    Returns a metadata dict, or None if the file module is unavailable.
    """
    try:
        import os
        import tempfile
        from connectors.cyops_utilities.builtins import upload_file_to_cyops
    except Exception:
        return None

    tmp_path = None
    try:
        tmp_path = os.path.join(tempfile.gettempdir(), file_name)
        with open(tmp_path, 'wb') as fh:
            fh.write(content)

        # Preferred signature (matches FortiSOAR playbook usage).
        att = upload_file_to_cyops(file_path=tmp_path, filename=file_name,
                                   create_attachment=True, name=file_name)

        result = {'filename': file_name, 'attachment_iri': '', 'file_iri': ''}
        if isinstance(att, dict):
            result['attachment_iri'] = att.get('@id') or att.get('iri') or ''
            holder = att.get('file', '')
            if isinstance(holder, dict):
                result['file_iri'] = holder.get('@id', '') or ''
            elif holder:
                result['file_iri'] = str(holder)
            result['raw'] = att
        else:
            result['attachment_iri'] = str(att)
        return result
    except TypeError:
        # Different SDK signature - fall back to the content form.
        try:
            att = upload_file_to_cyops(file_name=file_name, file_content=content,
                                       file_type=content_type or 'application/octet-stream',
                                       save_as_attachment=True)
            return att if isinstance(att, dict) else {'attachment_iri': str(att)}
        except Exception as err:
            logger.warning('upload_file_to_cyops failed: {0}'.format(err))
            return None
    except Exception as err:
        logger.warning('Could not store recording as FortiSOAR attachment: {0}'.format(err))
        return None
    finally:
        try:
            if tmp_path and os.path.isfile(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def play_recording(config, params):
    """
    Download a PSM session recording.

    POST /PasswordVault/API/Recordings/{RecordingId}/Play

    The recording is returned as a FortiSOAR file ATTACHMENT, not as inline
    data. Large recordings (a 2-hour session is tens of MB) must not be pushed
    into the playbook record as a text blob - that is what makes a playbook step
    hang 'In Progress'. The raw video bytes are read with _request_bytes and are
    never text-decoded, so the stored file is a valid, playable recording.

    Output:
      {
        "recording_id": "...",
        "file_name": "cyberark_recording_<id>.avi",
        "content_type": "...",
        "size_bytes": <int>,
        "attachment_iri": "/api/3/attachments/<uuid>",
        "file": {"filename": "...", "attachment_iri": "...", "file_iri": "..."}
      }
    A playbook can append "attachment_iri" to the record's "attachments" field
    to show the recording as a downloadable attachment. When the FortiSOAR file
    module is unavailable (e.g. local testing), "file"/"attachment_iri" are
    replaced by "content_base64" so the intact bytes are still returned.
    """
    recording_id = params.get('recording_id')
    if not recording_id:
        raise ConnectorError('recording_id is required')

    with PrivilegeCloudClient(config) as client:
        url = client._build_url('recording_play', recording_id=recording_id)
        content, content_type = client._request_bytes('POST', url)

    if not content:
        raise ConnectorError('Recording {0} returned no data'.format(recording_id))

    safe_id = re.sub(r'[^A-Za-z0-9_.-]', '_', str(recording_id))
    file_name = 'cyberark_recording_{0}{1}'.format(
        safe_id, _recording_extension(content, content_type))

    result = {
        'recording_id': recording_id,
        'file_name': file_name,
        'content_type': content_type or 'application/octet-stream',
        'size_bytes': len(content),
    }

    attachment = _save_recording_as_file(file_name, content, result['content_type'])
    if attachment is not None:
        result['file'] = attachment
        if isinstance(attachment, dict) and attachment.get('attachment_iri'):
            # Surface the attachment IRI at the top level so a playbook can
            # append it to the alert's "attachments" field directly.
            result['attachment_iri'] = attachment['attachment_iri']
        return result

    # Fallback: FortiSOAR file module unavailable - return intact bytes as base64.
    import base64
    result['content_base64'] = base64.b64encode(content).decode('ascii')
    result['note'] = ('FortiSOAR file module unavailable; returned base64. '
                      'Decode and save with the detected extension to play.')
    return result


# ============================================================
# Vault / Credential Operations (FortiSOAR vault integration)
#
# These use the Privilege Cloud REST API Accounts endpoints
# instead of the legacy AIMWebService/CCP path.
# ============================================================

def get_credentials(config, params):
    """
    List all accounts in the configured vault safe.
    Uses: GET /PasswordVault/API/Accounts?filter=safeName eq {safe}&limit=1000
    """
    vault_safe = config.get('vault_safe') or config.get('Safe')
    if not vault_safe:
        raise ConnectorError('Vault safe name is not configured')

    with PrivilegeCloudClient(config) as client:
        url = client._build_url('accounts')
        query = {
            'filter': 'safeName eq {0}'.format(vault_safe),
            'limit': 1000,
        }
        result = client._request('GET', url, query_params=query)
        formatted = []
        for item in result.get('value', []):
            username = item.get('userName', '')
            formatted.append({
                'key': item.get('id'),
                'display_name': username if username else item.get('name', item.get('id')),
            })
        return formatted


def get_credentials_details(config, params):
    """
    Retrieve account metadata (masked) for vault display.
    Uses: GET /PasswordVault/API/Accounts/{AccountId}
    """
    secret_id = params.get('secret_id')
    if not secret_id:
        raise ConnectorError('secret_id is required')

    with PrivilegeCloudClient(config) as client:
        url = client._build_url('account_by_id', account_id=secret_id)
        account = client._request('GET', url)
        # Return masked fields for display
        display_fields = ['id', 'name', 'userName', 'address', 'platformId', 'safeName', 'secretType']
        formatted = []
        for field in display_fields:
            if field in account:
                formatted.append({
                    'field_name': field,
                    'value': account[field] if field != 'secretType' else account[field],
                })
        return formatted


def get_credential(config, params):
    """
    Retrieve the actual credential value.
    Uses: POST /PasswordVault/API/Accounts/{AccountId}/Password/Retrieve
    """
    secret_id = params.get('secret_id')
    if not secret_id:
        raise ConnectorError('secret_id is required')

    with PrivilegeCloudClient(config) as client:
        url = client._build_url('account_password', account_id=secret_id)
        password = client._request('POST', url)
        return {'password': password}


# ============================================================
# Operation Dispatch Table
# ============================================================

operations = {
    # Accounts
    'get_account': [get_account],
    'get_account_details': [get_account_details],
    'retrieve_account_password': [retrieve_account_password],
    'reconcile_credentials': [reconcile_credentials],

    # Safes
    'add_safe': [add_safe],
    'list_safes': [list_safes],
    'get_safe_details': [get_safe_details],
    'update_safe': [update_safe],
    'delete_safe': [delete_safe],

    # Safe Members
    'add_safe_member': [add_safe_member],
    'list_safe_members': [list_safe_members],
    'update_safe_member': [update_safe_member],
    'delete_safe_member': [delete_safe_member],

    # Account Groups
    'get_safe_account_groups': [get_safe_account_groups],
    'add_account_group_member': [add_account_group_member],
    'get_account_group_members': [get_account_group_members],
    'delete_account_group_member': [delete_account_group_member],

    # Users
    'add_user': [add_user],
    'get_users': [get_users],
    'get_user_details': [get_user_details],
    'update_user': [update_user],
    'delete_user': [delete_user],
    'reset_user_password': [reset_user_password],
    'activate_user': [activate_user],
    'add_user_to_group': [add_user_to_group],
    'get_groups': [get_groups],

    # Recordings
    'get_recordings': [get_recordings],
    'get_recording_details': [get_recording_details],
    'play_recording': [play_recording],

    # Vault integration
    'get_credentials': [get_credentials],
    'get_credentials_details': [get_credentials_details],
    'get_credential': [get_credential],
}
