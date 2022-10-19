# ACM/IDM login microservice

Microservice running on [mu.semte.ch](http://mu.semte.ch) providing the necessary endpoints to login/logout a user using ACM/IDM as OpenId provider. This backend service works together with `@lblod/ember-acmidm-login` in the frontend.

## Tutorials
### Add the login service to a stack
Add the following snippet to your `docker-compose.yml` to include the login service in your project.

```yaml
services:
  login:
    image: kanselarij/acmidm-login-service:2.1.0
    environment:
      MU_APPLICATION_AUTH_DISCOVERY_URL: "https://authenticatie-ti.vlaanderen.be/op"
      MU_APPLICATION_AUTH_CLIENT_ID: "my-client-id"
      MU_APPLICATION_AUTH_REDIRECT_URI: "https://VLIVIA-dev.vlaanderen.be/authorization/callback"
      MU_APPLICATION_AUTH_CLIENT_SECRET: "THIS IS OUR SECRET"
```

Add rules to the `dispatcher.ex` to dispatch requests to the login service. E.g. 

```elixir
  match "/sessions/*path" do
    Proxy.forward conn, path, "http://login/sessions/"
  end
```
The host `login` in the forward URL reflects the name of the login service in the `docker-compose.yml` file as defined above.

More information how to setup a mu.semte.ch project can be found in [mu-project](https://github.com/mu-semtech/mu-project).

## Reference
### Configuration
The following environment variables are required:
* `MU_APPLICATION_AUTH_DISCOVERY_URL` [string]: OpenId discovery URL for authentication
* `MU_APPLICATION_AUTH_CLIENT_ID` [string]: Client id of the application in ACM/IDM
* `MU_APPLICATION_AUTH_CLIENT_SECRET` [string]: Client secret of the application in ACM/IDM
* `MU_APPLICATION_AUTH_REDIRECT_URI` [string]: Redirect URI of the application configured in ACM/IDM

The following enviroment variables can optionally be configured:
* `REQUEST_TIMEOUT` [int]: Timeout in ms of OpenID HTTP requests (default `25000`)
* `REQUEST_RETRIES` [int]: Number of times to retry OpenID HTTP requests (default `2`)
* `MU_APPLICATION_AUTH_ROLE_CLAIM` [string]: Key of the claim that contains the user's roles (default `dkb_kaleidos_rol_3d`)
* `MU_APPLICATION_AUTH_USERID_CLAIM` [string]: Key of the claim that contains the user's ientifier (default `vo_id`)
* `MU_APPLICATION_AUTH_ACCOUNTID_CLAIM` [string]: Key of the claim that contains the account's identifier (default `sub`)
* `DEBUG_LOG_TOKENSETS`: When set, received tokenSet information is logged to the console.
* `LOG_SINK_URL`: When set, log tokenSet information to that configured sink.

### API

#### POST /sessions
Log the user in by creating a new session, i.e. attaching the user's account to a session.

Before creating a new session, the given authorization code gets exchanged for an access token with an OpenID Provider (ACM/IDM) using the configured discovery URL. The returned JWT access token is decoded to retrieve information to attach to the user, account and the session. If the OpenID Provider returns a valid access token, a new user and account are created if they don't exist yet and a the account is attached to the session. 

The data model and mapping of ACM/IDM claims is documented [here](https://github.com/kanselarij-vlaanderen/kaleidos-documentation/blob/master/data-model/authentication.md)

##### Request body
```javascript
{ authorizationCode: "secret" }
```

##### Response
###### 201 Created
On successful login with the newly created session in the response body:

```javascript
{
  "links": {
    "self": "sessions/current"
  },
  "data": {
    "type": "sessions",
    "id": "b178ba66-206e-4551-b41e-4a46983912c0"
    "relationships": {
      "account": {
        "links": {
          "related": "/accounts/8e38fb90-f15c-47e9-8d74-024a3112dd28"
        },
        "data": {
          "type": "accounts",
          "id": "8e38fb90-f15c-47e9-8d74-024a3112dd28"
        }
      },
      "membership": {
        "links": {
          "related": "/memberships/3ba43eea-28f4-4386-bc26-2476baeb8425"
        },
        "data": {
          "type": "memberships",
          "id": "3ba43eea-28f4-4386-bc26-2476baeb8425"
        }
      }
    }
  }
}
```

###### 400 Bad Request
- if session header is missing. The header should be automatically set by the [identifier](https://github.com/mu-semtech/mu-identifier).
- if the authorization code is missing

###### 401 Bad Request
- on login failure. I.e. failure to exchange the authorization code for a valid access token with ACM/IDM

###### 403 Bad Request
- if no valid user role can be found based on the received claim from ACM/IDM

#### DELETE /sessions/current
Log out the current user, i.e. remove the session associated with the current user's account.

##### Response
###### 204 No Content
On successful logout

###### 400 Bad Request
If session header is missing or invalid. The header should be automatically set by the [identifier](https://github.com/mu-semtech/mu-identifier).

#### GET /sessions/current
Get the current session

##### Response
###### 200 Created

```javascript
{
  "links": {
    "self": "sessions/current"
  },
  "data": {
    "type": "sessions",
    "id": "b178ba66-206e-4551-b41e-4a46983912c0"
    "relationships": {
      "account": {
        "links": {
          "related": "/accounts/8e38fb90-f15c-47e9-8d74-024a3112dd28"
        },
        "data": {
          "type": "accounts",
          "id": "8e38fb90-f15c-47e9-8d74-024a3112dd28"
        }
      },
      "membership": {
        "links": {
          "related": "/memberships/3ba43eea-28f4-4386-bc26-2476baeb8425"
        },
        "data": {
          "type": "memberships",
          "id": "3ba43eea-28f4-4386-bc26-2476baeb8425"
        }
      }
    }
  }
}
```

###### 400 Bad Request
If session header is missing or invalid. The header should be automatically set by the [identifier](https://github.com/mu-semtech/mu-identifier).
