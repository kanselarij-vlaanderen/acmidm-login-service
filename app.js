import { app } from 'mu';
import { getSessionIdHeader, error } from './utils';
import { getAccessTokenWithRetry } from './lib/openid';
import {
  removeOldSessions, removeCurrentSession,
  ensureUserAndAccount, insertNewSessionForAccount,
  selectAccountBySession, selectCurrentSession
} from './lib/session';
import { selectUserGroup, USER_GRAPH_URI } from './lib/user';
import request from 'request';

const allowNoRoleClaim = process.env.MU_APPLICATION_AUTH_ALLOW_NO_ROLE_CLAIM === 'true';

/**
 * Configuration validation on startup
 */
const requiredEnvironmentVariables = [
  'MU_APPLICATION_AUTH_DISCOVERY_URL',
  'MU_APPLICATION_AUTH_CLIENT_ID',
  'MU_APPLICATION_AUTH_CLIENT_SECRET',
  'MU_APPLICATION_AUTH_REDIRECT_URI',
  'MU_APPLICATION_AUTH_DEFAULT_GROUP_URI'
];
if (!allowNoRoleClaim) {
  requiredEnvironmentVariables.push('MU_APPLICATION_AUTH_ROLE_CLAIM');
}
requiredEnvironmentVariables.forEach(key => {
  if (!process.env[key]) {
    console.log(`Environment variable ${key} must be configured`);
    process.exit(1);
  }
});

const roleClaim = process.env.MU_APPLICATION_AUTH_ROLE_CLAIM;

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
 * @return [403] If no bestuurseenheid can be linked to the session
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
      tokenSet = await getAccessTokenWithRetry(authorizationCode);
    } catch (e) {
      console.log(`Failed to retrieve access token for authorization code: ${e.message || e}`);
      return res.status(401).end();
    }

    await removeOldSessions(sessionUri);

    const claims = tokenSet.claims;

    if (process.env['DEBUG_LOG_TOKENSETS']) {
      console.log(`Received tokenSet ${JSON.stringify(tokenSet)} including claims ${JSON.stringify(claims)}`);
    }

    if (process.env['LOG_SINK_URL']) {
      request.post({ url: process.env['LOG_SINK_URL'], body: tokenSet, json: true });
    }

    const { accountUri, accountId } = await ensureUserAndAccount(claims, USER_GRAPH_URI);
    let { groupUri, groupId, groupName } = await selectUserGroup(accountUri, claims, roleClaim, USER_GRAPH_URI);

    if (!groupUri || !groupId) {
      console.log(`User is not allowed to login. No user group found`);
      return res.header('mu-auth-allowed-groups', 'CLEAR').status(403).end();
    }

    const roles = (claims[roleClaim] || []).map(r => r.split(':')[0]);
    roles.push(groupName);
    const { sessionId } = await insertNewSessionForAccount(accountUri, sessionUri, groupUri, roles);

    const groupData = { type: 'bestuurseenheden', id: groupId, name: groupName };

    return res.header('mu-auth-allowed-groups', 'CLEAR').status(201).send({
      links: {
        self: '/sessions/current'
      },
      data: {
        type: 'sessions',
        id: sessionId,
        attributes: {
          roles: roles
        }
      },
      relationships: {
        account: {
          links: { related: `/accounts/${accountId}` },
          data: { type: 'accounts', id: accountId }
        },
        group: {
          links: { related: `/bestuurseenheden/${groupId}` },
          data: groupData
        }
      }
    });
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
    const { accountUri } = await selectAccountBySession(sessionUri, USER_GRAPH_URI);
    if (!accountUri) {
      return error(res, 'Invalid session');
    }

    await removeCurrentSession(sessionUri);

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
    const { accountUri, accountId } = await selectAccountBySession(sessionUri, USER_GRAPH_URI);
    if (!accountUri) {
      return error(res, 'Invalid session');
    }

    const { sessionId, groupId, groupName, roles } = await selectCurrentSession(accountUri);

    return res.status(200).send({
      links: {
        self: '/sessions/current'
      },
      data: {
        type: 'sessions',
        id: sessionId,
        attributes: {
          roles: roles
        }
      },
      provider: 'acmidm-oauth2',
      relationships: {
        account: {
          links: { related: `/accounts/${accountId}` },
          data: { type: 'accounts', id: accountId }
        },
        group: {
          links: { related: `/bestuurseenheden/${groupId}` },
          data: { type: 'bestuurseenheden', id: groupId, name: groupName }
        }
      }
    });
  } catch (e) {
    return next(new Error(e.message));
  }
});

/**
 * Error handler translating thrown Errors to 500 HTTP responses
*/
app.use(function (err, req, res, next) {
  console.log(`Error: ${err.message}`);
  res.status(500);
  res.json({
    errors: [ { title: err.message } ]
  });
});
