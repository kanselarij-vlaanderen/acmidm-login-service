import { uuid, sparqlEscapeUri, sparqlEscapeString, sparqlEscapeDateTime, sparqlEscapeInt } from 'mu';
import { querySudo as query, updateSudo as update } from './auth-sudo';
import { ensureUser, ensureOrganisationsForUser } from './user';
import { ORG_GRAPH_URI } from './organization';

const serviceHomepage = 'https://github.com/lblod/acmidm-login-service';
const resourceBaseUri = process.env.MU_APPLICATION_RESOURCE_BASE_URI || 'http://data.lblod.info/';
const accountResourceBaseUri = `${resourceBaseUri}id/account/`;
const sessionResourceBaseUri = `${resourceBaseUri}id/session/`;
const tokenResourceBaseUri = `${resourceBaseUri}id/token/`;

const accountIdClaim = process.env.MU_APPLICATION_AUTH_ACCOUNTID_CLAIM || 'vo_id';

const SESSION_GRAPH_URI = 'http://mu.semte.ch/graphs/sessions';
const GROUP_GRAPH_URI = process.env.MU_APPLICATION_GRAPH; // As it was

const removeOldSessions = async function (sessionUri) {
  await update(
    `PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
     PREFIX session: <http://mu.semte.ch/vocabularies/session/>
     PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
     PREFIX dcterms: <http://purl.org/dc/terms/>

     DELETE WHERE {
       GRAPH <${SESSION_GRAPH_URI}> {
           ${sparqlEscapeUri(sessionUri)} session:account ?account .
           ?session                       session:account ?account ;
                                          mu:uuid ?id ;
                                          dcterms:modified ?modified ;
                                          ext:sessionRole ?role ;
                                          ext:sessionGroup ?group .
       }
     }`);
};

const removeCurrentSession = async function (sessionUri) {
  await removeOldSessions(sessionUri);
};

const ensureUserAndAccount = async function (claims, userGraphUri) {
  const { personUri } = await ensureUser(claims, userGraphUri);
  const { accountUri, accountId } = await ensureAccountForUser(personUri, claims, userGraphUri);
  ensureOrganisationsForUser(personUri, claims, ORG_GRAPH_URI, userGraphUri); // Fire and forget, non-critical data must not hold up the authentication flow
  return { accountUri, accountId };
};

const ensureAccountForUser = async function (personUri, claims, graph) {
  const accountId = claims[accountIdClaim];

  const queryResult = await query(`
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX dcterms: <http://purl.org/dc/terms/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>

    SELECT ?account ?accountId ?email ?phone
    FROM <${graph}> {
        ${sparqlEscapeUri(personUri)} foaf:account ?account .
        ?account a foaf:OnlineAccount ;
            mu:uuid ?accountId ;
            dcterms:identifier ${sparqlEscapeString(accountId)} .
    }`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return { accountUri: result.account.value, accountId: result.accountId.value };
  } else {
    const { accountUri, accountId } = await insertNewAccountForUser(personUri, claims, graph);
    return { accountUri, accountId };
  }
};

const insertNewAccountForUser = async function (person, claims, graph) {
  const accountId = uuid();
  const account = `${accountResourceBaseUri}${accountId}`;
  const now = new Date();

  let insertData = `
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX dcterms: <http://purl.org/dc/terms/>
    PREFIX acmidm: <http://mu.semte.ch/vocabularies/ext/acmidm/>

    INSERT DATA {
      GRAPH <${graph}> {
        ${sparqlEscapeUri(person)} foaf:account ${sparqlEscapeUri(account)} .
        ${sparqlEscapeUri(account)} a foaf:OnlineAccount ;
                                 mu:uuid ${sparqlEscapeString(accountId)} ;
                                 foaf:accountServiceHomepage ${sparqlEscapeUri(serviceHomepage)} ;
                                 dcterms:identifier ${sparqlEscapeString(claims[accountIdClaim])} ;
                                 dcterms:created ${sparqlEscapeDateTime(now)} .
    `;

  if (claims.vo_doelgroepcode) {
    insertData += `${sparqlEscapeUri(account)} acmidm:doelgroepCode ${sparqlEscapeString(claims.vo_doelgroepcode)} . `;
  }
  if (claims.vo_doelgroepnaam) {
    insertData += `${sparqlEscapeUri(account)} acmidm:doelgroepNaam ${sparqlEscapeString(claims.vo_doelgroepnaam)} . `;
  }

  insertData += `
      }
    }
  `;

  await update(insertData);

  return { accountUri: account, accountId: accountId };
};

const insertNewSessionForAccount = async function (accountUri, sessionUri, groupUri, roles, oauthTokenValue, oauthTokenExpirytime, oauthTokenEndpoint) {
  const muSessionId = uuid();
  const acmSessionUri = sessionResourceBaseUri + uuid();
  const acmTokenUri = tokenResourceBaseUri + uuid();
  const now = new Date();

  let insertData = `
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX dcterms: <http://purl.org/dc/terms/>
    PREFIX oauth-2.0: <http://kanselarij.vo.data.gift/vocabularies/oauth-2.0-session/>

    INSERT DATA {
      GRAPH <${SESSION_GRAPH_URI}> {
        ${sparqlEscapeUri(sessionUri)} mu:uuid ${sparqlEscapeString(muSessionId)} ;
                                 session:account ${sparqlEscapeUri(accountUri)} ;
                                 ext:sessionGroup ${sparqlEscapeUri(groupUri)} ;`;
  if (roles && roles.length) {
    insertData += `
                                 ext:sessionRole ${roles.map(r => sparqlEscapeString(r)).join(', ')} ;`;
  }

  insertData += `
                                 dcterms:modified ${sparqlEscapeDateTime(now)} .
        ${sparqlEscapeUri(acmSessionUri)} a oauth-2.0:OauthSession ;
          oauth-2.0:authenticates ${sparqlEscapeUri(sessionUri)} ;
          oauth-2.0:hasTokenValue ${sparqlEscapeUri(acmTokenUri)} ;
          oauth-2.0:hasEndpointURI ${sparqlEscapeUri(oauthTokenEndpoint)} .
        ${sparqlEscapeUri(acmTokenUri)} a oauth-2.0:BearerToken ;
          dcterms:created ${sparqlEscapeDateTime(now)} .
          oauth-2.0:hasTokenValue ${sparqlEscapeString(oauthTokenValue)} ;
          oauth-2.0:hasExpiryTime ${sparqlEscapeDateTime(oauthTokenExpirytime)} .
      }
    }`;

  await update(insertData);
  return { sessionUri, muSessionId };
};

const selectAccountBySession = async function (session, accountGraphUri) {
  const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX besluit: <http://data.vlaanderen.be/ns/besluit#>

    SELECT ?account ?accountId
    WHERE {
      GRAPH <${SESSION_GRAPH_URI}> {
          ${sparqlEscapeUri(session)} session:account ?account ;
                                      ext:sessionGroup ?group .
      }
      GRAPH <${GROUP_GRAPH_URI}> {
          ?group a foaf:Group ;
                 mu:uuid ?groupId .
      }
      GRAPH <${accountGraphUri}> {
          ?account a foaf:OnlineAccount ;
                   mu:uuid ?accountId .
      }
    }`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return { accountUri: result.account.value, accountId: result.accountId.value };
  } else {
    return { accountUri: null, accountId: null };
  }
};

const selectCurrentSession = async function (account) {
  const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>

    SELECT ?session ?sessionId ?group ?groupName ?groupId (GROUP_CONCAT(?role; SEPARATOR = ',') as ?roles)
    WHERE {
      GRAPH <${SESSION_GRAPH_URI}> {
          ?session session:account ${sparqlEscapeUri(account)} ;
                   mu:uuid ?sessionId ;
                   ext:sessionGroup ?group ;
                   ext:sessionRole ?role .
      }
      GRAPH <${GROUP_GRAPH_URI}> {
          ?group mu:uuid ?groupId .
          ?group foaf:name ?groupName .
      }
    } GROUP BY ?session ?sessionId ?group ?groupName ?groupId`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return {
      sessionUri: result.session.value,
      sessionId: result.sessionId.value,
      groupUri: result.group.value,
      groupId: result.groupId.value,
      groupName: result.groupName.value,
      roles: result.roles.value.split(',')
    };
  } else {
    return { sessionUri: null, sessionId: null, groupUri: null, groupId: null, roles: null };
  }
};

export {
  GROUP_GRAPH_URI,
  removeOldSessions,
  removeCurrentSession,
  ensureUserAndAccount,
  insertNewSessionForAccount,
  selectAccountBySession,
  selectCurrentSession
};
