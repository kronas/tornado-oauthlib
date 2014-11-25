#!/usr/bin/env python
# coding=utf-8


import os
import logging
import datetime
from functools import wraps

from oauthlib.common import to_unicode, add_params_to_uri, Request
from oauthlib.oauth2 import FatalClientError, OAuth2Error, AccessDeniedError,\
    RequestValidator, Server

from ..utils import decode_base64, create_response, import_string

__all__ = ('OAuth2Provider', 'OAuth2RequestValidator')

log = logging.getLogger('tornado_oauthlib')


class OAuth2Server(Server):

    def create_authorization_response(self, uri, http_method='GET', body=None,
                                      headers=None, scopes=None,
                                      credentials=None,
                                      handler=None):
        """Extract response_type and route to the designated handler."""
        request = Request(
            uri, http_method=http_method, body=body, headers=headers)
        request.scopes = scopes
        # TODO: decide whether this should be a required argument
        request.user = None     # TODO: explain this in docs
        request.handler = handler
        for k, v in (credentials or {}).items():
            setattr(request, k, v)
        response_type_handler = self.response_types.get(
            request.response_type, self.default_response_type_handler)
        log.debug('Dispatching response_type %s request to %r.',
                  request.response_type, response_type_handler)
        return response_type_handler.create_authorization_response(
            request, self.default_token_type)

    def create_token_response(self, uri, http_method='GET', body=None,
                              headers=None, credentials=None, handler=None):
        """Extract grant_type and route to the designated handler."""
        request = Request(
            uri, http_method=http_method, body=body, headers=headers)
        request.handler = handler
        request.scopes = None
        request.extra_credentials = credentials
        grant_type_handler = self.grant_types\
            .get(request.grant_type, self.default_grant_type_handler)
        log.debug('Dispatching grant_type %s request to %r.',
                  request.grant_type, grant_type_handler)
        return grant_type_handler.create_token_response(
            request, self.default_token_type)


class OAuth2Provider(object):

    def __init__(self, app=None):
        self._invalid_response = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        This callback can be used to initialize an application for the
        oauth provider instance.
        """
        self.app = app
        self._init_error_uri()
        self._init_server()

    def _init_error_uri(self):
        self.error_uri = self.app.settings.get('OAUTH2_PROVIDER_ERROR_URI',
                                               '/oauth/errors')

    def _init_server(self):
        expires_in = self.app.settings.\
            get('OAUTH2_PROVIDER_TOKEN_EXPIRES_IN')
        token_generator = self.app.settings.get(
            'OAUTH2_PROVIDER_TOKEN_GENERATOR', None
        )
        if token_generator and not callable(token_generator):
            token_generator = import_string(token_generator)

        refresh_token_generator = self.app.settings.get(
            'OAUTH2_PROVIDER_REFRESH_TOKEN_GENERATOR', None
        )
        if refresh_token_generator and\
           not callable(refresh_token_generator):
            refresh_token_generator =\
                import_string(refresh_token_generator)

        if hasattr(self, '_validator'):
            self.server = OAuth2Server(
                self._validator,
                token_expires_in=expires_in,
                token_generator=token_generator,
                refresh_token_generator=refresh_token_generator,
            )
        elif hasattr(self, '_clientgetter') and \
            hasattr(self, '_tokengetter') and \
            hasattr(self, '_tokensetter') and \
            hasattr(self, '_grantgetter') and \
                hasattr(self, '_grantsetter'):

            usergetter = None
            if hasattr(self, '_usergetter'):
                usergetter = self._usergetter

            validator = OAuth2RequestValidator(
                clientgetter=self._clientgetter,
                tokengetter=self._tokengetter,
                grantgetter=self._grantgetter,
                usergetter=usergetter,
                tokensetter=self._tokensetter,
                grantsetter=self._grantsetter,
            )
            self._validator = validator
            self.server = OAuth2Server(
                validator,
                token_expires_in=expires_in,
                token_generator=token_generator,
                refresh_token_generator=refresh_token_generator,
            )
        else:
            raise RuntimeError('application not bound to required getters')

    def invalid_response(self, f):
        """Register a function for responsing with invalid request.
        When an invalid request proceeds to :meth:`require_oauth`, we can
        handle the request with the registered function. The function
        accepts one parameter, which is an oauthlib Request object::
            @oauth.invalid_response
            def invalid_require_oauth(req):
                return jsonify(message=req.error_message), 401
        If no function is registered, it will return with ``abort(401)``.
        """
        self._invalid_response = f
        return f

    def clientgetter(self, f):
        """Register a function as the client getter.
        The function accepts one parameter `client_id`, and it returns
        a client object with at least these information:
            - client_id: A random string
            - client_secret: A random string
            - client_type: A string represents if it is `confidential`
            - redirect_uris: A list of redirect uris
            - default_redirect_uri: One of the redirect uris
            - default_scopes: Default scopes of the client
        The client may contain more information, which is suggested:
            - allowed_grant_types: A list of grant types
            - allowed_response_types: A list of response types
            - validate_scopes: A function to validate scopes
        Implement the client getter::
            @oauth.clientgetter
            def get_client(client_id):
                client = get_client_model(client_id)
                # Client is an object
                return client
        """
        self._clientgetter = f
        return f

    def usergetter(self, f):
        """Register a function as the user getter.
        This decorator is only required for **password credential**
        authorization::
            @oauth.usergetter
            def get_user(username, password, client, request,
                         *args, **kwargs):
                # client: current request client
                if not client.has_password_credential_permission:
                    return None
                user = User.get_user_by_username(username)
                if not user.validate_password(password):
                    return None
                # parameter `request` is an OAuthlib Request object.
                # maybe you will need it somewhere
                return user
        """
        self._usergetter = f
        return f

    def tokengetter(self, f):
        """Register a function as the token getter.
        The function accepts an `access_token` or `refresh_token` parameters,
        and it returns a token object with at least these information:
            - access_token: A string token
            - refresh_token: A string token
            - client_id: ID of the client
            - scopes: A list of scopes
            - expires: A `datetime.datetime` object
            - user: The user object
        The implementation of tokengetter should accepts two parameters,
        one is access_token the other is refresh_token::
            @oauth.tokengetter
            def bearer_token(access_token=None, refresh_token=None):
                if access_token:
                    return get_token(access_token=access_token)
                if refresh_token:
                    return get_token(refresh_token=refresh_token)
                return None
        """
        self._tokengetter = f
        return f

    def tokensetter(self, f):
        """Register a function to save the bearer token.
        The setter accepts two parameters at least, one is token,
        the other is request::
            @oauth.tokensetter
            def set_token(token, request, *args, **kwargs):
                save_token(token, request.client, request.user)
        The parameter token is a dict, that looks like::
            {
                u'access_token': u'6JwgO77PApxsFCU8Quz0pnL9s23016',
                u'token_type': u'Bearer',
                u'expires_in': 3600,
                u'scope': u'email address'
            }
        The request is an object, that contains an user object and a
        client object.
        """
        self._tokensetter = f
        return f

    def grantgetter(self, f):
        """Register a function as the grant getter.
        The function accepts `client_id`, `code` and more::
            @oauth.grantgetter
            def grant(client_id, code):
                return get_grant(client_id, code)
        It returns a grant object with at least these information:
            - delete: A function to delete itself
        """
        self._grantgetter = f
        return f

    def grantsetter(self, f):
        """Register a function to save the grant code.
        The function accepts `client_id`, `code`, `request` and more::
            @oauth.grantsetter
            def set_grant(client_id, code, request, *args, **kwargs):
                save_grant(client_id, code, request.user, request.scopes)
        """
        self._grantsetter = f
        return f

    def confirm_authorization_request(self, handler):
        """When consumer confirm the authorization."""
        server = self.server
        scope = handler.get_argument('scope', '')
        scopes = scope.split()
        credentials = dict(
            client_id=handler.get_argument('client_id'),
            redirect_uri=handler.get_argument('redirect_uri', None),
            response_type=handler.get_argument('response_type', None),
            state=handler.get_argument('state', None),
        )
        log.debug('Fetched credentials from request %r.', credentials)
        redirect_uri = credentials.get('redirect_uri')
        log.debug('Found redirect_uri %s.', redirect_uri)

        uri, http_method, body, headers = handler.request.uri,\
            handler.request.method, handler.request.body,\
            handler.request.headers
        try:
            ret = server.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials, handler)
            log.debug('Authorization successful.')
            create_response(handler, *ret)
        except FatalClientError as e:
            log.debug('Fatal client error %r', e)
            return handler.redirect(e.in_uri(self.error_uri))
        except OAuth2Error as e:
            log.debug('OAuth2Error: %r', e)
            return handler.redirect(e.in_uri(redirect_uri or
                                             self.error_uri))
        except Exception as e:
            log.warn('Exception: %r', e)
            return handler.redirect(add_params_to_uri(
                self.error_uri, {'error': 'unknown'}
            ))

    def authorize_handler(self, original_handler):
        """Authorization handler decorator.
        This decorator will sort the parameters and headers out, and
        pre validate everything::
            # '/oauth/authorize'
            @oauth2.authorize_handler
            class AuthorizeHandler

                def get(self, *args, **kwargs):
                    # render a page for user to confirm the
                    # authorization
                    client_id = kwargs.get('client_id')
                    client = Client.get(client_id=client_id)
                    kwargs['client'] = client
                    return self.render('oauthorize.html', **kwargs)

                def post(self):
                    confirm = self.get_argument('confirm', 'no')
                    return confirm == 'yes'
        """
        _get = original_handler.get
        _post = original_handler.post

        def _authorize(handler, *args, **kwargs):
            redirect_uri = handler.get_argument('redirect_uri', None)
            try:
                if handler.request.method == 'POST':
                    rv = _post(handler, *args, **kwargs)
                else:
                    rv = _get(handler, *args, **kwargs)
            except FatalClientError as e:
                log.debug('Fatal client error %r', e)
                return handler.redirect(e.in_uri(self.error_uri))
            except OAuth2Error as e:
                log.debug('OAuth2Error: %r', e)
                return handler.redirect(e.in_uri(redirect_uri or
                                                 self.error_uri))
            except Exception as e:
                log.warn('Exception: %r', e)
                return handler.redirect(add_params_to_uri(
                    self.error_uri, {'error': 'unknown'}
                ))

            if not isinstance(rv, bool):
                # if is a response or redirect
                return rv

            if not rv:
                # denied by user
                e = AccessDeniedError()
                return handler.redirect(e.in_uri(redirect_uri))
            return self.confirm_authorization_request(handler)

        def get(handler, *args, **kwargs):
            server = self.server
            uri, http_method, body, headers = handler.request.uri,\
                handler.request.method, handler.request.body,\
                handler.request.headers
            redirect_uri = handler.get_argument('redirect_uri', None)
            log.debug('Found redirect_uri %s.', redirect_uri)
            try:
                ret = server.validate_authorization_request(
                    uri, http_method, body, headers
                )
                scopes, credentials = ret
                kwargs['scopes'] = scopes
                kwargs.update(credentials)
            except FatalClientError as e:
                log.debug('Fatal client error %r', e)
                return handler.redirect(e.in_uri(self.error_uri))
            except OAuth2Error as e:
                log.debug('OAuth2Error: %r', e)
                return handler.redirect(e.in_uri(redirect_uri or
                                                 self.error_uri))
            except Exception as e:
                log.warn('Exception: %r', e)
                return handler.redirect(add_params_to_uri(
                    self.error_uri, {'error': 'unknown'}
                ))
            _authorize(handler, *args, **kwargs)

        def post(handler, *args, **kwargs):
            _authorize(handler, *args, **kwargs)

        original_handler.get = get
        original_handler.post = post
        return original_handler

    def token_handler(self, original_handler):
        """Access/refresh token handler decorator.
        The decorated function should return an dictionary or None as
        the extra credentials for creating the token response.
        You can control the access method with standard flask route
        mechanism. If you only allow the `POST` method::
            # '/oauth/token'
            @oauth2.token_handler
            class Tokenhandler(RequestHandler):
                def post(self):
                    pass
        """
        _post = original_handler.post

        def post(handler, *args, **kwargs):
            server = self.server
            uri, http_method, body, headers = handler.request.uri,\
                handler.request.method, handler.request.body,\
                handler.request.headers
            credentials = _post(handler, *args, **kwargs) or {}
            log.debug('Fetched extra credentials, %r.', credentials)
            ret = server.create_token_response(
                uri, http_method, body, headers, credentials, handler
            )
            create_response(handler, *ret)
        original_handler.post = post
        return original_handler

    def revoke_handler(self, original_handler):
        """Access/refresh token revoke decorator.
        Any return value by the decorated function will get discarded as
        defined in [`RFC7009`_].
        You can control the access method with the standard flask routing
        mechanism, as per [`RFC7009`_] it is recommended to only allow
        the `POST` method::
            # '/oauth/revoke'
            @oauth2.revoke_handler
            class Revokehandler(RequestHandler):
                def post(self):
                    pass
        .. _`RFC7009`: http://tools.ietf.org/html/rfc7009
        """
        def post(handler, *args, **kwargs):
            server = self.server

            token = handler.get_argument('token')
            handler.add_header('token_type_hint',
                               handler.get_argument('token_type_hint'))
            if token:
                handler.add_header('token', token)
            uri, http_method, body, headers = handler.request.uri,\
                handler.request.method, handler.request.body,\
                handler.request.headers
            ret = server.create_revocation_response(
                uri, headers=headers, body=body, http_method=http_method)
            return create_response(handler, *ret)
        original_handler.post = post
        return original_handler

    def verify_request(self, handler, scopes):
        """Verify current request, get the oauth data.
        If you can't use the ``require_oauth`` decorator, you can fetch
        the data in your request body::
            def get(self):
                valid, req = oauth2.verify_request(self, ['email'])
                if valid:
                    return self.finish()
                return self.send_error()
        """
        uri, http_method, body, headers = handler.request.uri,\
            handler.request.method, handler.request.body,\
            handler.request.headers
        return self.server.verify_request(
            uri, http_method, body, headers, scopes
        )

    def require_oauth(self, *scopes):
        """Protect resource with specified scopes."""
        def wrapper(f):
            @wraps(f)
            def decorated(handler, *args, **kwargs):
                if hasattr(handler, 'oauth') and handler.oauth:
                    return f(handler, *args, **kwargs)

                valid, req = self.verify_request(handler, scopes)

                if not valid:
                    if self._invalid_response:
                        return self._invalid_response(req)
                    return handler.send_error(401)
                handler.oauth = req
                return f(handler, *args, **kwargs)
            return decorated
        return wrapper

    def with_oauth(self, *scopes):
        """Protect resource with specified scopes."""
        def wrapper(f):
            @wraps(f)
            def decorated(handler, *args, **kwargs):
                if hasattr(handler, 'oauth') and handler.oauth:
                    return f(handler, *args, **kwargs)

                valid, req = self.verify_request(handler, scopes)

                if valid:
                    handler.oauth = req
                return f(handler, *args, **kwargs)
            return decorated
        return wrapper


class OAuth2RequestValidator(RequestValidator):

    def __init__(self, clientgetter, tokengetter, grantgetter,
                 usergetter=None, tokensetter=None, grantsetter=None):
        self._clientgetter = clientgetter
        self._tokengetter = tokengetter
        self._usergetter = usergetter
        self._tokensetter = tokensetter
        self._grantgetter = grantgetter
        self._grantsetter = grantsetter

    def client_authentication_required(self, request, *args, **kwargs):
        if request.grant_type == 'password':
            client = self._clientgetter(request.client_id)
            return (not client) or client.client_type == 'confidential' or\
                request.client_secret

        auth_required = ('authorization_code', 'refresh_token')
        return 'Authorization' in request.headers and\
            request.grant_type in auth_required

    def authenticate_client(self, request, *args, **kwargs):
        auth = request.headers.get('Authorization', None)
        log.debug('Authenticate client %r', auth)
        if auth:
            try:
                _, s = auth.split(' ')
                client_id, client_secret = decode_base64(s).split(':')
                client_id = to_unicode(client_id, 'utf-8')
                client_secret = to_unicode(client_secret, 'utf-8')
            except Exception as e:
                log.debug('Authenticate client failed with exception: %r',
                          e)
                return False
        else:
            client_id = request.client_id
            client_secret = request.client_secret

        client = self._clientgetter(client_id)
        if not client:
            log.debug('Authenticate client failed, client not found.')
            return False

        request.client = client
        if client.client_secret != client_secret:
            log.debug('Authenticate client failed, secret not match.')
            return False

        if client.client_type != 'confidential':
            log.debug('Authenticate client failed, not confidential.')
            return False
        log.debug('Authenticate client success.')
        return True

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Authenticate a non-confidential client.
        :param client_id: Client ID of the non-confidential client
        :param request: The Request object passed by oauthlib
        """
        log.debug('Authenticate client %r.', client_id)
        client = request.client or self._clientgetter(client_id)
        if not client:
            log.debug('Authenticate failed, client not found.')
            return False

        # attach client on request for convenience
        request.client = client
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
                             *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.
        This method is used in the authorization code grant flow. It will
        compare redirect_uri and the one in grant token strictly, you can
        add a `validate_redirect_uri` function on grant for a customized
        validation.
        """
        client = client or self._clientgetter(client_id)
        log.debug('Confirm redirect uri for client %r and code %r.',
                  client.client_id, code)
        grant = self._grantgetter(client_id=client.client_id, code=code)
        if not grant:
            log.debug('Grant not found.')
            return False
        if hasattr(grant, 'validate_redirect_uri'):
            return grant.validate_redirect_uri(redirect_uri)
        log.debug('Compare redirect uri for grant %r and %r.',
                  grant.redirect_uri, redirect_uri)

        testing = 'OAUTHLIB_INSECURE_TRANSPORT' in os.environ
        if testing and redirect_uri is None:
            # For testing
            return True

        return grant.redirect_uri == redirect_uri

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        """Get the list of scopes associated with the refresh token.
        This method is used in the refresh token grant flow.  We return
        the scope of the token to be refreshed so it can be applied to the
        new access token.
        """
        log.debug('Obtaining scope of refreshed token.')
        tok = self._tokengetter(refresh_token=refresh_token)
        return tok.scopes

    def confirm_scopes(self, refresh_token, scopes, request, *args,
                       **kwargs):
        """Ensures the requested scope matches the scope originally granted
        by the resource owner. If the scope is omitted it is treated as
        equal to the scope originally granted by the resource owner.
        DEPRECATION NOTE: This method will cease to be used in
        oauthlib>0.4.2, future versions of ``oauthlib`` use the validator
        method ``get_original_scopes`` to determine the scope of the
        refreshed token.
        """
        if not scopes:
            log.debug('Scope omitted for refresh token %r', refresh_token)
            return True
        log.debug('Confirm scopes %r for refresh token %r',
                  scopes, refresh_token)
        tok = self._tokengetter(refresh_token=refresh_token)
        return set(tok.scopes) == set(scopes)

    def get_default_redirect_uri(self, client_id, request, *args,
                                 **kwargs):
        """Default redirect_uri for the given client."""
        request.client = request.client or\
            self._clientgetter(client_id)
        redirect_uri = request.client.default_redirect_uri
        log.debug('Found default redirect uri %r', redirect_uri)
        return redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """Default scopes for the given client."""
        request.client = request.client or\
            self._clientgetter(client_id)
        scopes = request.client.default_scopes
        log.debug('Found default scopes %r', scopes)
        return scopes

    def invalidate_authorization_code(self, client_id, code, request,
                                      *args, **kwargs):
        """Invalidate an authorization code after use.
        We keep the temporary code in a grant, which has a `delete`
        function to destroy itself.
        """
        log.debug('Destroy grant token for client %r, %r', client_id, code)
        grant = self._grantgetter(client_id=client_id, code=code)
        if grant:
            grant.delete()

    def save_authorization_code(self, client_id, code, request,
                                *args, **kwargs):
        """Persist the authorization code."""
        log.debug(
            'Persist authorization code %r for client %r',
            code, client_id
        )
        request.client = request.client or\
            self._clientgetter(client_id)

        self._grantsetter(client_id, code, request, *args, **kwargs)

        return request.client.default_redirect_uri

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Persist the Bearer token."""
        log.debug('Save bearer token %r', token)
        self._tokensetter(token, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        """Validate access token.
        :param token: A string of random characters
        :param scopes: A list of scopes
        :param request: The Request object passed by oauthlib
        The validation validates:
            1) if the token is available
            2) if the token has expired
            3) if the scopes are available
        """
        log.debug('Validate bearer token %r', token)
        tok = self._tokengetter(access_token=token)
        if not tok:
            msg = 'Bearer token not found.'
            request.error_message = msg
            log.debug(msg)
            return False

        # validate expires
        if datetime.datetime.utcnow() > tok.expires:
            msg = 'Bearer token is expired.'
            request.error_message = msg
            log.debug(msg)
            return False

        # validate scopes
        if not set(tok.scopes).issuperset(set(scopes)):
            msg = 'Bearer token scope not valid.'
            request.error_message = msg
            log.debug(msg)
            return False

        request.access_token = tok
        request.user = tok.user
        request.scopes = scopes

        if hasattr(tok, 'client'):
            request.client = tok.client
        elif hasattr(tok, 'client_id'):
            request.client = self._clientgetter(tok.client_id)
        return True

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a valid and active client."""
        log.debug('Validate client %r', client_id)
        client = request.client or self._clientgetter(client_id)
        if client:
            # attach client to request object
            request.client = client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args,
                      **kwargs):
        """Ensure the grant code is valid."""
        client = client or self._clientgetter(client_id)
        log.debug(
            'Validate code for client %r and code %r', client.client_id,
            code
        )
        grant = self._grantgetter(client_id=client.client_id, code=code)
        if not grant:
            log.debug('Grant not found.')
            return False
        if hasattr(grant, 'expires') and \
           datetime.datetime.utcnow() > grant.expires:
            log.debug('Grant is expired.')
            return False

        request.state = kwargs.get('state')
        request.user = grant.user
        request.scopes = grant.scopes
        return True

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        """Ensure the client is authorized to use the grant type requested.
        It will allow any of the four grant types (`authorization_code`,
        `password`, `client_credentials`, `refresh_token`) by default.
        Implemented `allowed_grant_types` for client object to authorize
        the request.
        It is suggested that `allowed_grant_types` should contain at least
        `authorization_code` and `refresh_token`.
        """
        if self._usergetter is None and grant_type == 'password':
            log.debug('Password credential authorization is disabled.')
            return False

        default_grant_types = (
            'authorization_code', 'password',
            'client_credentials', 'refresh_token',
        )

        if grant_type not in default_grant_types:
            return False

        if hasattr(client, 'allowed_grant_types') and \
           grant_type not in client.allowed_grant_types:
            return False

        if grant_type == 'client_credentials':
            if not hasattr(client, 'user'):
                log.debug('Client should have a user property')
                return False
            request.user = client.user

        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request,
                              *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.
        This method is used in the authorization code grant flow and also
        in implicit grant flow. It will detect if redirect_uri in client's
        redirect_uris strictly, you can add a `validate_redirect_uri`
        function on grant for a customized validation.
        """
        request.client = request.client or self._clientgetter(client_id)
        client = request.client
        if hasattr(client, 'validate_redirect_uri'):
            return client.validate_redirect_uri(redirect_uri)
        return redirect_uri in client.redirect_uris

    def validate_refresh_token(self, refresh_token, client, request,
                               *args, **kwargs):
        """Ensure the token is valid and belongs to the client
        This method is used by the authorization code grant indirectly by
        issuing refresh tokens, resource owner password credentials grant
        (also indirectly) and the refresh token grant.
        """

        token = self._tokengetter(refresh_token=refresh_token)

        if token and token.client_id == client.client_id:
            # Make sure the request object contains user and client_id
            request.client_id = token.client_id
            request.user = token.user
            return True
        return False

    def validate_response_type(self, client_id, response_type, client,
                               request, *args, **kwargs):
        """Ensure client is authorized to use the response type requested.
        It will allow any of the two (`code`, `token`) response types by
        default. Implemented `allowed_response_types` for client object
        to authorize the request.
        """
        if response_type not in ('code', 'token'):
            return False

        if hasattr(client, 'allowed_response_types'):
            return response_type in client.allowed_response_types
        return True

    def validate_scopes(self, client_id, scopes, client, request,
                        *args, **kwargs):
        """Ensure the client is authorized access to requested scopes."""
        if hasattr(client, 'validate_scopes'):
            return client.validate_scopes(scopes)
        return set(client.default_scopes).issuperset(set(scopes))

    def validate_user(self, username, password, client, request,
                      *args, **kwargs):
        """Ensure the username and password is valid.
        Attach user object on request for later using.
        """
        log.debug('Validating username %r and password %r',
                  username, password)
        if self._usergetter is not None:
            user = self._usergetter(
                username, password, client, request, *args, **kwargs
            )
            if user:
                request.user = user
                return True
            return False
        log.debug('Password credential authorization is disabled.')
        return False

    def revoke_token(self, token, token_type_hint, request,
                     *args, **kwargs):
        """Revoke an access or refresh token.
        """
        if token_type_hint:
            tok = self._tokengetter(**{token_type_hint: token})
        else:
            tok = self._tokengetter(access_token=token)
            if not tok:
                tok = self._tokengetter(refresh_token=token)

        if tok and tok.client_id == request.client.client_id:
            request.client_id = tok.client_id
            request.user = tok.user
            tok.delete()
            return True

        msg = 'Invalid token supplied.'
        log.debug(msg)
        request.error_message = msg
        return False
