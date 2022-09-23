import { uuid, sparqlEscapeUri, sparqlEscapeString, sparqlEscapeDateTime } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';
import { RESOURCE_BASE_URI, USERS_GRAPH } from '../config';

const ensureMembership = async function (personUri, roleUri, organizationUri) {
  const organizationStatement = organizationUri ? `?membership org:organization ${sparqlEscapeUri(organizationUri)} .` : '';

  const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX dct: <http://purl.org/dc/terms/>
    PREFIX org: <http://www.w3.org/ns/org#>

    SELECT ?membership ?membershipId
    WHERE {
      GRAPH <${USERS_GRAPH}> {
        ?membership a org:Membership ;
          mu:uuid ?membershipId ;
          org:member ${sparqlEscapeUri(personUri)} ;
          org:role ${sparqlEscapeUri(roleUri)} .
        ${organizationStatement}
      }
    } LIMIT 1`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return { membershipUri: result.membership.value, membershipId: result.membershipId.value };
  } else {
    const membership = await insertNewMembership(personUri, roleUri, organizationUri);
    return { membershipUri: membership.uri, membershipId: membership.id };
  }
};

const insertNewMembership = async function (personUri, roleUri, organizationUri) {
  const id = uuid();
  const membershipUri = `${RESOURCE_BASE_URI}/lidmaatschap/${id}`;

  const now = new Date();

  const organizationStatement = organizationUri ? `${sparqlEscapeUri(membershipUri)} org:organization ${sparqlEscapeUri(organizationUri)} .` : '';

  await update(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX dct: <http://purl.org/dc/terms/>
    PREFIX org: <http://www.w3.org/ns/org#>

    INSERT DATA {
      GRAPH <${USERS_GRAPH}> {
        ${sparqlEscapeUri(membershipUri)} a org:Membership ;
           mu:uuid ${sparqlEscapeString(id)} ;
           org:member ${sparqlEscapeUri(personUri)} ;
           org:role ${sparqlEscapeUri(roleUri)} ;
           dct:created ${sparqlEscapeDateTime(now)} .
        ${organizationStatement}
      }
    }`);

  return { uri: membershipUri, id };
};

export {
  ensureMembership
}
