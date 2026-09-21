import { uuid, sparqlEscapeUri, sparqlEscapeString, sparqlEscapeDateTime } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';
import { ACCESS_ALLOWED_STATUS_URI, RESOURCE_BASE_URI, USERS_GRAPH } from '../config';

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

  let membership;
  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    membership = { uri: result.membership.value, id: result.membershipId.value, status: result.status.value };
  } else {
    membership = await insertNewMembership(personUri, roleUri, organizationUri);
  }

  await removeOutdatedMembershipsForOrganization(personUri, roleUri, organizationUri);

  return { membershipUri: membership.uri, membershipId: membership.id, membershipStatus: membership.status };
};

const removeOutdatedMembershipsForOrganization = async function (personUri, roleUri, organizationUri) {
  await update(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX org: <http://www.w3.org/ns/org#>

    DELETE {
      GRAPH <${USERS_GRAPH}> {
        ?membership ?p ?o .
      }
    } WHERE {
      GRAPH <${USERS_GRAPH}> {
        ?membership a org:Membership ;
          org:member ${sparqlEscapeUri(personUri)} ;
          org:role ?role ;
          org:organization ${sparqlEscapeUri(organizationUri)} ;
          ?p ?o .
        FILTER (?role != ${sparqlEscapeUri(roleUri)})
      }
    }`);
};

const insertNewMembership = async function (personUri, roleUri, organizationUri) {
  const id = uuid();
  const membershipUri = `${RESOURCE_BASE_URI}/lidmaatschap/${id}`;

  const now = new Date();

  let status = ACCESS_ALLOWED_STATUS_URI;
  const result = await query(`
  PREFIX adms: <http://www.w3.org/ns/adms#>

  SELECT ?organizationStatus
  WHERE {
    GRAPH <${USERS_GRAPH}> {
      ${sparqlEscapeUri(organizationUri)} adms:status ?organizationStatus .
    }
  } LIMIT 1`);

  if (result.results.bindings.length) {
    status = result.results.bindings[0].organizationStatus.value;
  }

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
           org:organization ${sparqlEscapeUri(organizationUri)} ;
           adms:status ${sparqlEscapeUri(status)} ;
           dct:created ${sparqlEscapeDateTime(now)} .
      }
    }`);

  return { uri: membershipUri, id, status};
};

export {
  ensureMembership
}
