import { app, errorHandler } from 'mu';
import { getSessionIdHeader, error } from './utils';
import { getAccessToken } from './lib/openid';
import { removeSession, ensureUserResources, insertNewSession, selectCurrentSession, selectUserRole, sessionIsAuthorized, removeAllSessionsByUserId, removeAllSessionsBeforeDatetime, removeAllSessions } from './lib/session';
import request from 'request';
import { ACCESS_BLOCKED_STATUS_URI } from './config';
import { BlockedError } from './lib/exception';
import { insertLoginActivity } from './lib/login-activity';

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
        const { accountUri, accountId, personUri, membershipUri, membershipId } = await ensureUserResources(claims, role);
        const { sessionId } = await insertNewSession(sessionUri, accountUri, membershipUri);
        await insertLoginActivity(personUri);
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
 * @return [403] If the user or membership linked to this session are blocked
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

    // We only check the user and membership status here. If an organization is
    // blocked that translates to the membership being blocked, which we handle.
    // We don't check the organization status itself so that unblocking the
    // membership actually has effect.
    if (session.userStatus === ACCESS_BLOCKED_STATUS_URI) {
      console.log(`User <${session.userUri}> is blocked`);
      return res.header('mu-auth-allowed-groups', 'CLEAR').status(403).end();
    }

    if (session.membershipStatus === ACCESS_BLOCKED_STATUS_URI) {
      console.log(`User's membership <${session.membershipUri}> is blocked`);
      return res.header('mu-auth-allowed-groups', 'CLEAR').status(403).end();
    }

    await insertLoginActivity(session.userUri);

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

/**
 * Delete sessions based on a number of parameters
 * The accepted parameters are:
 * - ?uuid=<id>: delete all sessions belonging to the user with the given UUID
 * - ?beforeDatetime=ISO-timestamp: delete all sessions before the given timestamp
 * If no parameters are supplied, all sessions will be cleared.
 */
app.delete('/sessions', async function (req, res, next) {
  const sessionUri = req.headers['mu-session-id'];
  const { uuid, beforeDatetime } = req.query;

  if (uuid && beforeDatetime) {
    return next({ message: 'Setting both the uuid and beforeDatetime parameters in the same call is not supported', status: 400 });
  }

  const date = new Date(beforeDatetime);
  if (beforeDatetime && Number.isNaN(date.valueOf())) {
    return next({ message: `beforeDatetime should be a correctly formatted ISO timestamp, you provided: "${beforeDatetime}"`, status: 400 });
  }

  if (!(await sessionIsAuthorized(sessionUri))) {
    return next({ message: 'You do not have the correct role to perform this operation', status: 401 });
  }

  if (uuid) {
    await removeAllSessionsByUserId(uuid);
  } else if (beforeDatetime) {
    await removeAllSessionsBeforeDatetime(date);
  } else {
    await removeAllSessions();
  }
  return res.status(204).end();
});

app.use(errorHandler);
