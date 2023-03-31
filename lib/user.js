import { uuid, sparqlEscapeUri, sparqlEscapeString, sparqlEscapeDateTime } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';
import {
  RESOURCE_BASE_URI,
  USERS_GRAPH,
  AUTH_USERID_CLAIM,
  AUTH_FIRST_NAME_CLAIM,
  AUTH_FAMILY_NAME_CLAIM,
  AUTH_EMAIL_CLAIM,
  parseEmailFromClaim,
  ACCESS_ALLOWED_STATUS_URI
} from '../config';

const emailToUri = function (email) {
  // "test@example.com" to "mailto:test@example.com"
  return `mailto:${email}`;
};

const uriToEmail = function (uri) {
  // "mailto:test@example.com" to "test@example.com"
  return uri.replace(/^mailto:/, '');
};

const ensureUser = async function (claims) {
  const userIdentifier = claims[AUTH_USERID_CLAIM];

  if (userIdentifier) {
    const queryResult = await query(`
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX dct: <http://purl.org/dc/terms/>
    PREFIX adms: <http://www.w3.org/ns/adms#>

    SELECT ?person ?firstName ?familyName ?email ?status
    WHERE {
      GRAPH <${USERS_GRAPH}> {
        ?person a foaf:Person ;
          adms:status ?status ;
          dct:identifier ${sparqlEscapeString(userIdentifier)} .
        OPTIONAL { ?person foaf:firstName ?firstName . }
        OPTIONAL { ?person foaf:familyName ?familyName . }
        OPTIONAL { ?person foaf:mbox ?email . }
      }
    }`);

    if (queryResult.results.bindings.length) {
      const result = queryResult.results.bindings[0];
      const personUri = result.person.value;
      // Fire and forget, non-critical data must not hold up the authentication flow
      ensureFreshUserData({
        uri: personUri,
        firstName: result.firstName?.value,
        familyName: result.familyName?.value,
        email: result.email ? uriToEmail(result.email.value) : undefined
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
    {
      predicate: 'http://xmlns.com/foaf/0.1/firstName',
      oldValue: person.firstName,
      newValue: sparqlEscapeString(claims[AUTH_FIRST_NAME_CLAIM])
    },
    {
      predicate: 'http://xmlns.com/foaf/0.1/familyName',
      oldValue: person.familyName,
      newValue: sparqlEscapeString(claims[AUTH_FAMILY_NAME_CLAIM])
    },
    {
      predicate: 'http://xmlns.com/foaf/0.1/mbox',
      oldValue: person.email,
      newValue: claims[AUTH_EMAIL_CLAIM] ? sparqlEscapeUri(emailToUri(parseEmailFromClaim(claims[AUTH_EMAIL_CLAIM]))) : undefined }
  ];

  for (const { predicate, oldValue, newValue } of properties) {
    if (oldValue != newValue) {
      await update(`
        DELETE WHERE {
          GRAPH <${USERS_GRAPH}> {
            ${sparqlEscapeUri(person.uri)} ${sparqlEscapeUri(predicate)} ?value .
        }
      }`);

      if (newValue) {
        await update(`
        INSERT DATA {
          GRAPH <${USERS_GRAPH}> {
            ${sparqlEscapeUri(person.uri)} ${sparqlEscapeUri(predicate)} ${newValue)} .
          }
        }`);
      }
    }
  }
};

export {
  ensureUser
};
