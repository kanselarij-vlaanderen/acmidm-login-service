import { uuid, sparqlEscapeUri, sparqlEscapeString, sparqlEscapeDateTime } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';
import { ensureOrganization } from './organization';
import { ensureUser } from './user';
import { ensureAccountForUser } from './account';
import { ensureMembership } from './membership';
import { SESSIONS_GRAPH, USERS_GRAPH, PUBLIC_GRAPH, AUTH_ROLE_CLAIM, parseRoleFromClaim, ACCESS_BLOCKED_STATUS_URI } from '../config';
import { BlockedError } from './exception';

const ROLES = {
  ADMIN: 'http://themis.vlaanderen.be/id/gebruikersrol/9a969b13-e80b-424f-8a82-a402bcb42bc5',
}

const removeSession = async function (sessionUri) {
  await update(
    `PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
     PREFIX session: <http://mu.semte.ch/vocabularies/session/>
     PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
     PREFIX dct: <http://purl.org/dc/terms/>

     DELETE WHERE {
       GRAPH <${SESSIONS_GRAPH}> {
           ${sparqlEscapeUri(sessionUri)} mu:uuid ?id ;
                                          session:account ?account ;
                                          ext:sessionMembership ?membership ;
                                          dct:modified ?modified .
       }
     }`);
};

const selectUserRole = async function (claims) {
  const roleClaims = claims[AUTH_ROLE_CLAIM] || [];
  if (roleClaims.length > 1) {
    console.log(`Received multiple role claims from ACM/IDM while only one was expected: ${roleClaims.join(', ')}. Going to use the first one in the list.`);
  }
  const roleClaim = roleClaims[0];
  const notation = parseRoleFromClaim(roleClaim);
  if (notation) {
    const queryResult = await query(`
      PREFIX org: <http://www.w3.org/ns/org#>
      PREFIX skos: <http://www.w3.org/2004/02/skos/core#>

      SELECT ?role
      WHERE {
        GRAPH <${PUBLIC_GRAPH}> {
          ?role a org:Role ; skos:notation ${sparqlEscapeString(notation)} .
        }
      } LIMIT 1
    `);
    if (queryResult.results.bindings.length) {
      const result = queryResult.results.bindings[0];
      return result.role.value;
    } else {
      console.log(`Cannot find role with notation "${notation}" passed in claim "${roleClaim}" by ACM/IDM`);
      return null;
    }
  } else {
    console.log(`Unable to parse role from claim "${roleClaim}" passed by ACM/IDM`);
    return null;
  }
};

const ensureUserResources = async function (claims, roleUri) {
  const { organizationUri } = await ensureOrganization(claims);
  if (!organizationUri) {
    throw Error('User cannot be linked to an organization');
  }

  const { personUri, personStatus } = await ensureUser(claims);
  const { accountUri, accountId } = await ensureAccountForUser(personUri, claims);
  const { membershipUri, membershipId, membershipStatus } = await ensureMembership(personUri, roleUri, organizationUri);

  // We only check the user and membership status here. If an organization is
  // blocked that translates to the membership being blocked, which we handle.
  // We don't check the organization status itself so that unblocking the
  // membership actually has effect.
  if (personStatus === ACCESS_BLOCKED_STATUS_URI) {
    throw new BlockedError(`User <${personUri}> is blocked`);
  }
  if (membershipStatus === ACCESS_BLOCKED_STATUS_URI) {
    throw new BlockedError(`User's membership <${membershipUri}> is blocked`);
  }

  return { accountUri, accountId, personUri, membershipUri, membershipId };
};

const insertNewSession = async function (sessionUri, accountUri, membershipUri) {
  const sessionId = uuid();
  const now = new Date();

  await update(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX dct: <http://purl.org/dc/terms/>

    INSERT DATA {
      GRAPH <${SESSIONS_GRAPH}> {
        ${sparqlEscapeUri(sessionUri)} mu:uuid ${sparqlEscapeString(sessionId)} ;
                                 session:account ${sparqlEscapeUri(accountUri)} ;
                                 ext:sessionMembership ${sparqlEscapeUri(membershipUri)} ;
                                 dct:modified ${sparqlEscapeDateTime(now)} .
      }
    }`);

  return { sessionUri, sessionId };
};

const selectCurrentSession = async function (session) {
  const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX org: <http://www.w3.org/ns/org#>
    PREFIX adms: <http://www.w3.org/ns/adms#>

    SELECT ?id ?account ?accountId ?membership ?membershipId ?user ?userStatus ?organizationStatus ?membershipStatus
    WHERE {
      GRAPH <${SESSIONS_GRAPH}> {
        ${sparqlEscapeUri(session)} mu:uuid ?id ;
          session:account ?account ;
          ext:sessionMembership ?membership .
      }
      GRAPH <${USERS_GRAPH}> {
        ?account a foaf:OnlineAccount ;
          mu:uuid ?accountId .
        ?membership a org:Membership ;
          adms:status ?membershipStatus ;
          org:member ?user ;
          org:organization / adms:status ?organizationStatus ;
          mu:uuid ?membershipId .
        ?user adms:status ?userStatus .
      }
    }`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return {
      uri: session,
      id: result.id.value,
      accountUri: result.account.value,
      accountId: result.accountId.value,
      membershipUri: result.membership.value,
      membershipId: result.membershipId.value,
      userUri: result.user.value,
      userStatus: result.userStatus.value,
      organizationStatus: result.organizationStatus.value,
      membershipStatus: result.membershipStatus.value,
    };
  } else {
    return { uri: session };
  }
};

const sessionIsAuthorized = async function (sessionUri) {
  const roleUris = [
    ROLES.ADMIN,
  ];

  const queryString = `PREFIX session: <http://mu.semte.ch/vocabularies/session/>
PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
PREFIX org: <http://www.w3.org/ns/org#>

ASK {
  VALUES (?roleUri) {
    ${roleUris.map(uri => `(${sparqlEscapeUri(uri)})`).join(`
    `)}
  }

  ${sparqlEscapeUri(sessionUri)} session:account ?account ;
    ext:sessionMembership / org:role ?roleUri .
}`;
  const response = await query(queryString);
  return response.boolean;
}

const removeAllSessions = async function () {
  await update(
    `PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
     PREFIX session: <http://mu.semte.ch/vocabularies/session/>
     PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
     PREFIX dct: <http://purl.org/dc/terms/>

     DELETE {
       GRAPH <${SESSIONS_GRAPH}> {
           ?s ?p ?o .
       }
     } WHERE {
       GRAPH <${SESSIONS_GRAPH}> {
           ?s ?p ?o .
           FILTER( STRSTARTS( STR(?s), "http://mu.semte.ch/sessions/" ) )
       }
     }`);
}

const removeAllSessionsByUserId = async function (userId) {
  await update(
    `PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
     PREFIX session: <http://mu.semte.ch/vocabularies/session/>
     PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
     PREFIX dct: <http://purl.org/dc/terms/>
     PREFIX foaf: <http://xmlns.com/foaf/0.1/>

     DELETE {
       GRAPH <${SESSIONS_GRAPH}> {
           ?session mu:uuid ?id ;
                    session:account ?account ;
                    ext:sessionMembership ?membership ;
                    dct:modified ?modified .
       }
     } WHERE {
       GRAPH <${USERS_GRAPH}> {
           ?person a foaf:Person ;
                   dct:identifier ${sparqlEscapeString(userId)} ;
                   foaf:account ?account .
       }
       GRAPH <${SESSIONS_GRAPH}> {
           ?session mu:uuid ?id ;
                    session:account ?account ;
                    ext:sessionMembership ?membership ;
                    dct:modified ?modified .
       }
     }`);
};

const removeAllSessionsBeforeDatetime = async function (datetime) {
  await update(
    `PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
     PREFIX session: <http://mu.semte.ch/vocabularies/session/>
     PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
     PREFIX dct: <http://purl.org/dc/terms/>

     DELETE {
       GRAPH <${SESSIONS_GRAPH}> {
           ?session mu:uuid ?id ;
                    session:account ?account ;
                    ext:sessionMembership ?membership ;
                    dct:modified ?modified .
       }
     } WHERE {
       GRAPH <${SESSIONS_GRAPH}> {
           ?session mu:uuid ?id ;
                    session:account ?account ;
                    ext:sessionMembership ?membership ;
                    dct:modified ?modified .
           FILTER( STRSTARTS( STR(?session), "http://mu.semte.ch/sessions/" ) )
           FILTER( ?modified < ${sparqlEscapeDateTime(datetime)} )
       }
     }`);
};

export {
  removeSession,
  selectUserRole,
  ensureUserResources,
  insertNewSession,
  selectCurrentSession,
  sessionIsAuthorized,
  removeAllSessions,
  removeAllSessionsByUserId,
  removeAllSessionsBeforeDatetime,
};
