import { uuid, sparqlEscapeUri, sparqlEscapeString, sparqlEscapeDateTime } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';
import { RESOURCE_BASE_URI, USERS_GRAPH, ACCOUNT_SERVICE_HOMEPAGE, AUTH_ACCOUNTID_CLAIM } from '../config';

const ensureAccountForUser = async function (personUri, claims) {
  const accountId = claims[AUTH_ACCOUNTID_CLAIM];

  const queryResult = await query(`
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>

    SELECT ?account ?accountId
    WHERE {
      GRAPH <${USERS_GRAPH}> {
        ${sparqlEscapeUri(personUri)} foaf:account ?account .
        ?account a foaf:OnlineAccount ;
          mu:uuid ?accountId ;
          foaf:accountName ${sparqlEscapeString(accountId)} .
      }
    } LIMIT 1`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return { accountUri: result.account.value, accountId: result.accountId.value };
  } else {
    const account = await insertNewAccountForUser(personUri, claims);
    return { accountUri: account.uri, accountId: account.id };
  }
};

const insertNewAccountForUser = async function (person, claims) {
  const id = uuid();
  const accountUri = `${RESOURCE_BASE_URI}/account/${id}`;

  const accountName = claims[AUTH_ACCOUNTID_CLAIM];
  const now = new Date();

  await update(`
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX dct: <http://purl.org/dc/terms/>

    INSERT DATA {
      GRAPH <${USERS_GRAPH}> {
        ${sparqlEscapeUri(person)} foaf:account ${sparqlEscapeUri(accountUri)} .
        ${sparqlEscapeUri(accountUri)} a foaf:OnlineAccount ;
                                 mu:uuid ${sparqlEscapeString(id)} ;
                                 foaf:accountServiceHomepage ${sparqlEscapeUri(ACCOUNT_SERVICE_HOMEPAGE)} ;
                                 foaf:accountName ${sparqlEscapeString(accountName)} ;
                                 dct:created ${sparqlEscapeDateTime(now)} .
      }
    }
  `);

  return { uri: accountUri, id: id };
};

export {
  ensureAccountForUser
}
