import { app, errorHandler } from 'mu';
import { getSessionIdHeader, error } from './utils';
import { getAccessToken } from './lib/openid';
import { removeSession, ensureUserResources, insertNewSession, selectCurrentSession, selectUserRole } from './lib/session';
import request from 'request';
import { ACCESS_BLOCKED_STATUS_URI } from './config';
import { blockMembership } from './lib/membership';
import { BlockedError } from './lib/exception';

/**
 * Configuration validation on startup
 */
const requiredEnvironmentVariables = [
  'MU_APPLICATION_AUTH_DISCOVERY_URL',
  'MU_APPLICATION_AUTH_CLIENT_ID',
  'MU_APPLICATION_AUTH_CLIENT_SECRET',
  'MU_APPLICATION_AUTH_REDIRECT_URI',
];

requiredEnvironmentVariables.forEach(key => {
  if (!process.env[key]) {
    console.log(`Environment variable ${key} must be configured`);
    process.exit(1);
  }
});


/**
 * Log the user in by creating a new session, i.e. attaching the user's account to a session.
 *
 * Before creating a new session, the given authorization code gets exchanged for an access token
 * with an OpenID Provider (ACM/IDM) using the configured discovery URL. The returned JWT access token
 * is decoded to retrieve information to attach to the user, account and the session.
 * If the OpenID Provider returns a valid access token, a new user and account are created if they
 * don't exist yet and a the account is attached to the session.
 *
 * Body: { authorizationCode: "secret" }
 *
 * @return [201] On successful login containing the newly created session
 * @return [400] If the session header or authorization code is missing
 * @return [401] On login failure (unable to retrieve a valid access token)
 * @return [403] If no role can be found, or if the user is blocked in some way
*/
app.post('/sessions', async function (req, res, next) {
  const sessionUri = getSessionIdHeader(req);
  if (!sessionUri) {
    return error(res, 'Session header is missing');
  }

  const authorizationCode = req.body['authorizationCode'];
  if (!authorizationCode) {
    return error(res, 'Authorization code is missing');
  }

  try {
    let tokenSet;
    try {
      tokenSet = await getAccessToken(authorizationCode);
    } catch (e) {
      console.log(`Failed to retrieve access token for authorization code.`);
      console.log(e);
      return res.header('mu-auth-allowed-groups', 'CLEAR').status(401).end();
    }

    await removeSession(sessionUri);

    const claims = tokenSet.claims();

    if (process.env['DEBUG_LOG_TOKENSETS']) {
      console.log(`Received tokenSet ${JSON.stringify(tokenSet)} including claims ${JSON.stringify(claims)}`);
    }

    if (process.env['LOG_SINK_URL']) {
      request.post({ url: process.env['LOG_SINK_URL'], body: tokenSet, json: true });
    }

    const role = await selectUserRole(claims);
    if (role) {
      try {
        const { accountUri, accountId, membershipUri, membershipId } = await ensureUserResources(claims, role);
        const { sessionId } = await insertNewSession(sessionUri, accountUri, membershipUri);
        return res.header('mu-auth-allowed-groups', 'CLEAR').status(201).send({
          links: {
            self: '/sessions/current'
          },
          data: {
            type: 'sessions',
            id: sessionId,
            relationships: {
              account: {
                links: { related: `/accounts/${accountId}` },
                data: { type: 'accounts', id: accountId }
              },
              membership: {
                links: { related: `/memberships/${membershipId}` },
                data: { type: 'memberships', id: membershipId }
              }
            }
          }
        });
      } catch (e) {
        if (e instanceof BlockedError) {
          console.log(e);
          return res.header('mu-auth-allowed-groups', 'CLEAR').status(403).end();
        } else {
          console.log(`Failed to create required user resources in order to authenticate session.`);
          console.log(e);
          return res.header('mu-auth-allowed-groups', 'CLEAR').status(401).end();
        }
      }
    } else {
      console.log(`User is not allowed to login. No user role found for claims passed by ACM/IDM.`);
      return res.header('mu-auth-allowed-groups', 'CLEAR').status(403).end();
    }
  } catch (e) {
    return next(new Error(e.message));
  }
});

/**
 * Log out from the current session, i.e. detaching the session from the user's account.
 *
 * @return [204] On successful logout
 * @return [400] If the session header is missing or invalid
*/
app.delete('/sessions/current', async function (req, res, next) {
  const sessionUri = getSessionIdHeader(req);
  if (!sessionUri) {
    return error(res, 'Session header is missing');
  }
  try {
    const { accountUri, membershipUri } = await selectCurrentSession(sessionUri);
    if (!accountUri || !membershipUri) {
      return error(res, 'Invalid session');
    }

    await removeSession(sessionUri);

    return res.header('mu-auth-allowed-groups', 'CLEAR').status(204).end();
  } catch (e) {
    return next(new Error(e.message));
  }
});

/**
 * Get the current session
 *
 * @return [200] The current session
 * @return [400] If the session header is missing or invalid
*/
app.get('/sessions/current', async function (req, res, next) {
  const sessionUri = getSessionIdHeader(req);
  if (!sessionUri) {
    return next(new Error('Session header is missing'));
  }

  try {
    const session = await selectCurrentSession(sessionUri);
    if (!session.accountUri || !session.membershipUri) {
      return error(res, 'Invalid session');
    }

    if (session.userStatus === ACCESS_BLOCKED_STATUS_URI) {
      res.status(403);
      return error(res, 'This user is blocked');
    }

    if (session.organizationStatus === ACCESS_BLOCKED_STATUS_URI) {
      await blockMembership(session.membershipUri);
      res.status(403);
      return error(res, 'This organization is blocked');
    }

    if (session.membershipStatus === ACCESS_BLOCKED_STATUS_URI) {
      res.status(403);
      return error(res, 'This membership is blocked');
    }

    return res.status(200).send({
      links: {
        self: '/sessions/current'
      },
      data: {
        type: 'sessions',
        id: session.id,
        provider: 'acmidm-oauth2',
        relationships: {
          account: {
            links: { related: `/accounts/${session.accountId}` },
            data: { type: 'accounts', id: session.accountId }
          },
          membership: {
            links: { related: `/memberships/${session.membershipId}` },
            data: { type: 'memberships', id: session.membershipId }
          }
        }
      }
    });
  } catch (e) {
    return next(new Error(e.message));
  }
});

app.use(errorHandler);
