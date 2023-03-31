import { uuid, sparqlEscapeUri, sparqlEscapeString } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';
import { RESOURCE_BASE_URI, USERS_GRAPH, AUTH_ORG_CODE_CLAIM, AUTH_ORG_NAME_CLAIM, ACCESS_ALLOWED_STATUS_URI } from '../config';

const ensureOrganization = async function (claims) {
  const orgCodeClaim = claims[AUTH_ORG_CODE_CLAIM]; // E.g. "OVO000032"

  if (orgCodeClaim) {
    const queryResult = await query(`
    PREFIX org: <http://www.w3.org/ns/org#>
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX skos: <http://www.w3.org/2004/02/skos/core#>
    PREFIX adms: <http://www.w3.org/ns/adms#>

    SELECT ?organization ?name ?status
    WHERE {
      GRAPH <${USERS_GRAPH}> {
        ?organization a foaf:Organization ;
            adms:status ?status ;
            org:identifier ${sparqlEscapeString(orgCodeClaim)} .
        OPTIONAL { ?organization skos:prefLabel ?name . }
      }
    } LIMIT 1`);

    if (queryResult.results.bindings.length) {
      const result = queryResult.results.bindings[0];
      // Fire and forget, non-critical data must not hold up the authentication flow
      ensureFreshOrganizationData({
        uri: result.organization.value,
        name: result.name?.value
      }, claims);
      return { organizationUri: result.organization.value, organizationStatus: result.status.value };
    } else {
      const organization = await insertNewOrganization(claims);
      return { organizationUri: organization.uri };
    }
  } else {
    console.log(`No organization code found in claims passed by ACM/IDM. Cannot relate user to an organization.`);
    return { organizationUri: null };
  }
};

const insertNewOrganization = async function (claims) {
  const id = uuid();
  const orgUri = `${RESOURCE_BASE_URI}/organisatie/${id}`;

  const orgCodeClaim = claims[AUTH_ORG_CODE_CLAIM]; // E.g. "OVO000032"
  const orgName = claims[AUTH_ORG_NAME_CLAIM];

  const orgNameStatement = orgName ? `${sparqlEscapeUri(orgUri)} skos:prefLabel ${sparqlEscapeString(orgName)} .` : '';

  await update(`
  PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
  PREFIX org: <http://www.w3.org/ns/org#>
  PREFIX foaf: <http://xmlns.com/foaf/0.1/>
  PREFIX skos: <http://www.w3.org/2004/02/skos/core#>
  PREFIX adms: <http://www.w3.org/ns/adms#>

  INSERT DATA {
    GRAPH <${USERS_GRAPH}> {
      ${sparqlEscapeUri(orgUri)} a foaf:Organization ;
         mu:uuid ${sparqlEscapeString(id)} ;
         adms:status ${sparqlEscapeUri(ACCESS_ALLOWED_STATUS_URI)} ;
         org:identifier ${sparqlEscapeString(orgCodeClaim)} .
      ${orgNameStatement}
    }
  }`);

  return { uri: orgUri, id };
};

const ensureFreshOrganizationData = async function (organization, claims) {
  const properties = [
    { predicate: 'skos:prefLabel', oldValue: organization.name, newValue: claims[AUTH_ORG_NAME_CLAIM] },
  ];

  for (const { predicate, oldValue, newValue } of properties) {
    if (oldValue != newValue) {
      await update(`
        PREFIX skos: <http://www.w3.org/2004/02/skos/core#>

        DELETE WHERE {
          GRAPH <${USERS_GRAPH}> {
            ${sparqlEscapeUri(organization.uri)} ${predicate} ?value .
        }
      }`);

      if (newValue) {
        await update(`
        PREFIX skos: <http://www.w3.org/2004/02/skos/core#>

        INSERT DATA {
          GRAPH <${USERS_GRAPH}> {
            ${sparqlEscapeUri(organization.uri)} ${predicate} ${sparqlEscapeString(newValue)} .
          }
        }`);
      }
    }
  }
};


export {
  ensureOrganization
};
