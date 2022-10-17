import { uuid, sparqlEscapeUri, sparqlEscapeString, sparqlEscapeDateTime } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';
import { ACCESS_BLOCKED_STATUS_URI, ACCESS_ALLOWED_STATUS_URI, RESOURCE_BASE_URI, USERS_GRAPH } from '../config';

const ensureMembership = async function (personUri, roleUri, organizationUri) {
  const organizationStatement = organizationUri ? `?membership org:organization ${sparqlEscapeUri(organizationUri)} .` : '';

  const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX dct: <http://purl.org/dc/terms/>
    PREFIX org: <http://www.w3.org/ns/org#>
    PREFIX adms: <http://www.w3.org/ns/adms#>

    SELECT ?membership ?membershipId ?status
    WHERE {
      GRAPH <${USERS_GRAPH}> {
        ?membership a org:Membership ;
          adms:status ?status ;
          mu:uuid ?membershipId ;
          org:member ${sparqlEscapeUri(personUri)} ;
          org:role ${sparqlEscapeUri(roleUri)} .
        ${organizationStatement}
      }
    } LIMIT 1`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    const status = result.status.value;
    if (status === ACCESS_BLOCKED_STATUS_URI) {
      throw new Error(`The user has been blocked and does not have access.`)
    }
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
    PREFIX adms: <http://www.w3.org/ns/adms#>

    INSERT DATA {
      GRAPH <${USERS_GRAPH}> {
        ${sparqlEscapeUri(membershipUri)} a org:Membership ;
           mu:uuid ${sparqlEscapeString(id)} ;
           org:member ${sparqlEscapeUri(personUri)} ;
           org:role ${sparqlEscapeUri(roleUri)} ;
           adms:status ${sparqlEscapeUri(ACCESS_ALLOWED_STATUS_URI)} ;
           dct:created ${sparqlEscapeDateTime(now)} .
        ${organizationStatement}
      }
    }`);

  return { uri: membershipUri, id };
};

export {
  ensureMembership
}
