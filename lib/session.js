import { uuid, sparqlEscapeUri, sparqlEscapeString, sparqlEscapeDateTime } from 'mu';
import { querySudo as query, updateSudo as update } from './auth-sudo';

const allowNoRoleClaim = process.env.MU_APPLICATION_AUTH_ALLOW_NO_ROLE_CLAIM === 'true';
const defaultGroupUri = process.env.MU_APPLICATION_AUTH_DEFAULT_GROUP_URI;

const serviceHomepage = 'https://github.com/lblod/acmidm-login-service';
const resourceBaseUri = process.env.MU_APPLICATION_RESOURCE_BASE_URI || 'http://data.lblod.info/';
const personResourceBaseUri = `${resourceBaseUri}id/persoon/`;
const accountResourceBaseUri = `${resourceBaseUri}id/account/`;
const identifierResourceBaseUri = `${resourceBaseUri}id/identificator/`;

const userIdClaim = process.env.MU_APPLICATION_AUTH_USERID_CLAIM || 'rrn';
const accountIdClaim = process.env.MU_APPLICATION_AUTH_ACCOUNTID_CLAIM || 'vo_id';


const removeOldSessions = async function(sessionUri) {
  await update(
    `PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
     PREFIX session: <http://mu.semte.ch/vocabularies/session/>
     PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
     PREFIX dcterms: <http://purl.org/dc/terms/>

     DELETE WHERE {
       GRAPH <http://mu.semte.ch/graphs/sessions> {
           ${sparqlEscapeUri(sessionUri)} session:account ?account .
           ?session                       session:account ?account ;
                                          mu:uuid ?id ;
                                          dcterms:modified ?modified ;
                                          ext:sessionRole ?role ;
                                          ext:sessionGroup ?group .
       }
     }`);
};

const removeCurrentSession = async function(sessionUri) {
  await removeOldSessions(sessionUri);
};

const ensureUserAndAccount = async function(claims, groupId) {
  const graph = `http://mu.semte.ch/graphs/public`;
  const { personUri } = await ensureUser(claims, graph);
  const { accountUri, accountId } = await ensureAccountForUser(personUri, claims, graph);
  return { accountUri, accountId };
};

const ensureUser = async function(claims, graph) {
  const userId = claims[userIdClaim];

  const queryResult = await query(`
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX adms: <http://www.w3.org/ns/adms#>
    PREFIX dcterms: <http://purl.org/dc/terms/>

    SELECT ?person ?personId
    FROM <${graph}> {
      ?person a foaf:Person ;
            mu:uuid ?personId ;
            adms:identifier ?identifier .
      ?identifier skos:notation ${sparqlEscapeString(userId)} .
    }`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    const personUri = result.person.value;
    await updateUserNames(personUri, claims, graph);
    return { personUri: personUri, personId: result.personId.value };
  } else {
    const { personUri, personId } = await insertNewUser(claims, graph);
    return { personUri, personId };
  }
};

const updateUserNames = async function(personUri, claims, graph){
  let updateQuery = `
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX adms: <http://www.w3.org/ns/adms#>
    PREFIX skos: <http://www.w3.org/2004/02/skos/core#>

    DELETE {
      GRAPH <${graph}> {
        ${sparqlEscapeUri(personUri)} foaf:firstName ?first ;
                                      foaf:familyName ?last .
      }
    } WHERE {
      GRAPH <${graph}> {
        ${sparqlEscapeUri(personUri)} a foaf:Person .
        OPTIONAL {
          ${sparqlEscapeUri(personUri)} foaf:firstName ?first .
        }
        OPTIONAL {
          ${sparqlEscapeUri(personUri)} foaf:familyName ?last .
        }
      }
    }`;

    await update(updateQuery);

    updateQuery = `
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX adms: <http://www.w3.org/ns/adms#>
    PREFIX skos: <http://www.w3.org/2004/02/skos/core#>

    INSERT DATA {
      GRAPH <${graph}> {
        ${sparqlEscapeUri(personUri)} a foaf:Person .
    `;

  if (claims.given_name)
    updateQuery += `${sparqlEscapeUri(personUri)} foaf:firstName ${sparqlEscapeString(claims.given_name)} . `;

  if (claims.family_name)
    updateQuery += `${sparqlEscapeUri(personUri)} foaf:familyName ${sparqlEscapeString(claims.family_name)} . `;

  updateQuery += `
      }
    }
  `;

  await update(updateQuery);
};

const insertNewUser = async function(claims, graph) {
  const personId = uuid();
  const person = `${personResourceBaseUri}${personId}`;
  const identifierId = uuid();
  const identifier = `${identifierResourceBaseUri}${identifierId}`;
  const now = new Date();

  let insertData = `
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX adms: <http://www.w3.org/ns/adms#>
    PREFIX skos: <http://www.w3.org/2004/02/skos/core#>

    INSERT DATA {
      GRAPH <${graph}> {
        ${sparqlEscapeUri(person)} a foaf:Person ;
                                 mu:uuid ${sparqlEscapeString(personId)} ;
                                 adms:identifier ${sparqlEscapeUri(identifier)} .
        ${sparqlEscapeUri(defaultGroupUri)} foaf:member ${sparqlEscapeUri(person)} .
        ${sparqlEscapeUri(identifier)} a adms:Identifier ;
                                       mu:uuid ${sparqlEscapeString(identifierId)} ;
                                       skos:notation ${sparqlEscapeString(claims[userIdClaim])} .
    `;

  if (claims.given_name)
    insertData += `${sparqlEscapeUri(person)} foaf:firstName ${sparqlEscapeString(claims.given_name)} . `;

  if (claims.family_name)
    insertData += `${sparqlEscapeUri(person)} foaf:familyName ${sparqlEscapeString(claims.family_name)} . `;

  insertData += `
      }
    }
  `;

  await update(insertData);

  return { personUri: person, personId: personId };
};

const ensureAccountForUser = async function(personUri, claims, graph) {
  const accountId = claims[accountIdClaim];

  const queryResult = await query(`
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX dcterms: <http://purl.org/dc/terms/>

    SELECT ?account ?accountId
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


const insertNewAccountForUser = async function(person, claims, graph) {
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

  if (claims.vo_doelgroepcode)
    insertData += `${sparqlEscapeUri(account)} acmidm:doelgroepCode ${sparqlEscapeString(claims.vo_doelgroepcode)} . `;

  if (claims.vo_doelgroepnaam)
    insertData += `${sparqlEscapeUri(account)} acmidm:doelgroepNaam ${sparqlEscapeString(claims.vo_doelgroepnaam)} . `;

  insertData += `
      }
    }
  `;

  await update(insertData);

  return { accountUri: account, accountId: accountId };
};

const insertNewSessionForAccount = async function(accountUri, sessionUri, groupUri, roles) {
  const sessionId = uuid();
  const now = new Date();

  let insertData = `
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX dcterms: <http://purl.org/dc/terms/>

    INSERT DATA {
      GRAPH <http://mu.semte.ch/graphs/sessions> {
        ${sparqlEscapeUri(sessionUri)} mu:uuid ${sparqlEscapeString(sessionId)} ;
                                 session:account ${sparqlEscapeUri(accountUri)} ;
                                 ext:sessionGroup ${sparqlEscapeUri(groupUri)} ;`;
  if (roles && roles.length)
    insertData += `
                                 ext:sessionRole ${roles.map(r => sparqlEscapeString(r)).join(', ')} ;
              `;

  insertData +=`                     dcterms:modified ${sparqlEscapeDateTime(now)} .
      }
    }`;

  await update(insertData);
  return { sessionUri, sessionId };
};

const selectUserGroup = async function (accountUri, claims, roleClaim) {
  if ((claims[roleClaim] && claims[roleClaim].length > 0) ||
    allowNoRoleClaim) {
    const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX besluit: <http://data.vlaanderen.be/ns/besluit#>

    SELECT ?group ?groupId ?groupName
    WHERE {
      GRAPH <http://mu.semte.ch/graphs/public> {
          ?user foaf:account <${accountUri}> .
          ?group foaf:member ?user.
          ?group foaf:name ?groupName.
          ?group mu:uuid ?groupId.
      }
    }`);

    if (queryResult.results.bindings.length) {
      const result = queryResult.results.bindings[0];
      return { groupUri: result.group.value, groupId: result.groupId.value, groupName: result.groupName.value };
    }
  }

  console.log("user is not allowed to access the application");
  return { groupUri: null, groupId: null, groupName: null };
};

const selectAccountBySession = async function(session) {
  const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX besluit: <http://data.vlaanderen.be/ns/besluit#>

    SELECT ?account ?accountId
    WHERE {
      GRAPH <http://mu.semte.ch/graphs/sessions> {
          ${sparqlEscapeUri(session)} session:account ?account ;
                                      ext:sessionGroup ?group .
      }
      GRAPH <${process.env.MU_APPLICATION_GRAPH}> {
          ?group a foaf:Group ;
                 mu:uuid ?groupId .
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

const selectCurrentSession = async function(account) {
  const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>

    SELECT ?session ?sessionId ?group ?groupName ?groupId (GROUP_CONCAT(?role; SEPARATOR = ',') as ?roles)
    WHERE {
      GRAPH <http://mu.semte.ch/graphs/sessions> {
          ?session session:account ${sparqlEscapeUri(account)} ;
                   mu:uuid ?sessionId ;
                   ext:sessionGroup ?group ;
                   ext:sessionRole ?role .
      }
      GRAPH <${process.env.MU_APPLICATION_GRAPH}> {
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
  removeOldSessions,
  removeCurrentSession,
  ensureUserAndAccount,
  insertNewSessionForAccount,
  selectUserGroup,
  selectAccountBySession,
  selectCurrentSession
}
