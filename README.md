# Tornado-OAuthlib

# Features

* Support OAuth2 provider with Bearer token

# Installation

```
$ pip install Tornado-OAuthlib
```

# Usage

## OAuth2 Provider

* initialize oauth2

```python
from tornado_oauthlib.provider import OAuth2Provider

oauth2 = OAuth2Provider()
```

* Client, Grant, Token examples using peewee

```python
class OAuth2Client(Model):
    class Meta:
        database = peewee_database
    name = CharField(max_length=40)
    description = TextField()
    user = ForeignKeyField(user_model, related_name='client')
    client_id = CharField(max_length=40, unique=True, primary_key=True)
    client_secret = CharField(max_length=55, unique=True, index=True)
    is_confidential = BooleanField(default=False)

    _redirect_uris = TextField()
    _default_scopes = TextField()

    @property
    def client_type(self):
        if self.is_confidential:
            return 'confidential'
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []

class OAuth2Grant(Model):
    class Meta:
        database = peewee_database
    id = PrimaryKeyField()
    user = ForeignKeyField(user_model, related_name='grant')
    client = ForeignKeyField(OAuth2Client, related_name='grant')
    code = CharField(max_length=255, index=True)
    redirect_uri = CharField(max_length=255)
    expires = DateTimeField()
    _scopes = TextField()

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

class OAuth2BearerToken(Model):
    class Meta:
        database = peewee_database
    id = PrimaryKeyField()
    user = ForeignKeyField(user_model, related_name='bearer_token')
    client = ForeignKeyField(OAuth2Client, related_name='bearer_token')
    token_type = CharField(max_length=40)
    access_token = CharField(max_length=255, unique=True)
    refresh_token = CharField(max_length=255, unique=True)
    expires = DateTimeField()
    _scopes = TextField()

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []
```

* Client getter

```python
@oauth2.clientgetter
def load_client(client_id):
    try:
        return OAuth2Client.get(OAuth2Client.client_id == client_id)
    except OAuth2Client.DoesNotExist:
        return None
```

* Grant getter and setter

```python
@oauth2.grantgetter
def load_grant(client_id, code):
    try:
        return OAuth2Grant.get(OAuth2Grant.client_id == client_id & OAuth2Grant.code == code)
    except OAuth2Grant.DoesNotExist:
        return None


@oauth2.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = OAuth2Grant(
        client=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=request.handler.get_current_user(),
        expires=expires
    )
    peewee_database.add(grant)
    peewee_database.commit()
    return grant
```

* Token getter and setter

```python
@oauth2.tokengetter
def load_token(access_token=None, refresh_token=None):
    try:
        if access_token:
            return OAuth2BearerToken.get(OAuth2BearerToken.access_token == access_token)
        elif refresh_token:
            return OAuth2BearerToken.get(OAuth2BearerToken.refresh_token == refresh_token)
    except OAuth2BearerToken.DoesNotExist:
        return None


@oauth2.tokensetter
def save_token(token, request, *args, **kwargs):
    if request.response_type == 'token':
        user = request.handler.get_current_user()
    else:
        user = request.user
    toks = OAuth2BearerToken.select()\
        .where(OAuth2BearerToken.client == request.client &
               OAuth2BearerToken.user == request.user)
    # make sure that every client has only one token connected to a user
    for t in toks:
        t.delete_instance()

    expires_in = token['expires_in']
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = OAuth2BearerToken(
        access_token=token['access_token'],
        refresh_token=token.get('refresh_token', None),
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client=request.client,
        user=request.user,
    )
    peewee_database.add(tok)
    peewee_database.commit()
    return tok
```

* User getter

```python
@oauth2.usergetter
def get_user(username, password, *args, **kwargs):
    try:
        user = User.get(User.username == username)
    except User.DoesNotExist:
        return None
    if user.verify(password):
        return user
    return None
```

* Authorize handler

```python
# '/oauth/authorize'
@oauth2.authorize_handler
class AuthorizeHandler(RequestHandler):

    def get(self, *args, **kwargs):
        client_id = kwargs.get('client_id')
        client = Client.get(client_id=client_id)
        kwargs['client'] = client
        self.render('oauthorize.html', **kwargs)

    def post(self):
        confirm = self.get_argument('confirm', 'no')
        return confirm == 'yes'
```

* Token handler

```python
# '/oauth/token'
@oauth2.token_handler
class Tokenhandler(RequestHandler):

    def post(self):
        return {'version': '0.1.0'}
```

* Revoke handler

```python
# '/oauth/revoke'
@oauth2.revoke_handler
class Revokehandler(RequestHandler):
    
    def post(self):
        pass
```

* Protect Resource

```python
class UserHandler(RequestHandler):
    @oauth2.require_oauth('email')
    def get(self):
        user = self.oauth.user
        self.finish(jsonify(email=user.email, username=user.username))
```
