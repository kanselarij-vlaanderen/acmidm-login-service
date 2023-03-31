import { uuid, sparqlEscapeUri, sparqlEscapeString, sparqlEscapeDateTime } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';
import { RESOURCE_BASE_URI, USERS_GRAPH, AUTH_USERID_CLAIM, AUTH_FIRST_NAME_CLAIM, AUTH_FAMILY_NAME_CLAIM, ACCESS_ALLOWED_STATUS_URI } from '../config';

const ensureUser = async function (claims) {
  const userIdentifier = claims[AUTH_USERID_CLAIM];

  if (userIdentifier) {
    const queryResult = await query(`
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX dct: <http://purl.org/dc/terms/>
    PREFIX adms: <http://www.w3.org/ns/adms#>

    SELECT ?person ?firstName ?familyName ?status
    WHERE {
      GRAPH <${USERS_GRAPH}> {
        ?person a foaf:Person ;
          adms:status ?status ;
          dct:identifier ${sparqlEscapeString(userIdentifier)} .
        OPTIONAL { ?person foaf:firstName ?firstName . }
        OPTIONAL { ?person foaf:familyName ?familyName . }
      }
    }`);

    if (queryResult.results.bindings.length) {
      const result = queryResult.results.bindings[0];
      const personUri = result.person.value;
      // Fire and forget, non-critical data must not hold up the authentication flow
      ensureFreshUserData({
        uri: personUri,
        firstName: result.firstName?.value,
        familyName: result.familyName?.value
      }, claims);
      return { personUri: personUri, personStatus: result.status.value };
    } else {
      const person = await insertNewUser(claims);
      return { personUri: person.uri, personStatus: person.status };
    }
  } else {
    throw new Error(`No user identifier found in claims passed by ACM/IDM. Cannot identify user.`);
  }
};

const insertNewUser = async function (claims) {
  const id = uuid();
  const personUri = `${RESOURCE_BASE_URI}/gebruiker/${id}`;
  const status = ACCESS_ALLOWED_STATUS_URI;

  const identifier = claims[AUTH_USERID_CLAIM];
  const firstName = claims[AUTH_FIRST_NAME_CLAIM];
  const familyName = claims[AUTH_FAMILY_NAME_CLAIM];
  const now = new Date();

  // Optional insert data statements
  const firstNameStatement = firstName ? `${sparqlEscapeUri(personUri)} foaf:firstName ${sparqlEscapeString(firstName)} .` : '';
  const familyNameStatement = familyName ? `${sparqlEscapeUri(personUri)} foaf:familyName ${sparqlEscapeString(familyName)} .` : '';

  await update(`
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX dct: <http://purl.org/dc/terms/>
    PREFIX adms: <http://www.w3.org/ns/adms#>

    INSERT DATA {
      GRAPH <${USERS_GRAPH}> {
        ${sparqlEscapeUri(personUri)} a foaf:Person ;
           mu:uuid ${sparqlEscapeString(id)} ;
           dct:identifier ${sparqlEscapeString(identifier)} ;
           adms:status ${sparqlEscapeUri(status)} ;
           dct:created ${sparqlEscapeDateTime(now)} .
        ${firstNameStatement}
        ${familyNameStatement}
      }
    }`);

  return { uri: personUri, id, status };
};

const ensureFreshUserData = async function (person, claims) {
  const properties = [
    { predicate: 'foaf:firstName', oldValue: person.firstName, newValue: claims[AUTH_FIRST_NAME_CLAIM] },
    { predicate: 'foaf:familyName', oldValue: person.familyName, newValue: claims[AUTH_FAMILY_NAME_CLAIM] }
  ];

  for (const { predicate, oldValue, newValue } of properties) {
    if (oldValue != newValue) {
      await update(`
        PREFIX foaf: <http://xmlns.com/foaf/0.1/>

        DELETE WHERE {
          GRAPH <${USERS_GRAPH}> {
            ${sparqlEscapeUri(person.uri)} ${predicate} ?value .
        }
      }`);

      if (newValue) {
        await update(`
        PREFIX foaf: <http://xmlns.com/foaf/0.1/>

        INSERT DATA {
          GRAPH <${USERS_GRAPH}> {
            ${sparqlEscapeUri(person.uri)} ${predicate} ${sparqlEscapeString(newValue)} .
          }
        }`);
      }
    }
  }
};

export {
  ensureUser
};
