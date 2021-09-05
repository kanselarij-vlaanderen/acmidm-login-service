import { uuid, sparqlEscapeUri, sparqlEscapeString } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';

const organisationResourceBaseUri = 'https://data.vlaanderen.be/id/organisatie/';
const ORG_GRAPH_URI = process.env.ORG_GRAPH_URI || 'http://mu.semte.ch/graphs/public';

const ovoCodeFromString = function (s) {
  const match = s.match(/OVO\d{6}/);
  return match ? match[0] : match;
};

const insertNewOrganization = async function (ovoCode, graph) {
  const id = uuid();
  const organizationUri = `${organisationResourceBaseUri}${ovoCode}`;

  const insertData = `
  PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
  PREFIX org: <http://www.w3.org/ns/org#>

  INSERT DATA {
    GRAPH <${graph}> {
      ${sparqlEscapeUri(organizationUri)} a org:Organization ;
         mu:uuid ${sparqlEscapeString(id)} ;
         org:identifier ${sparqlEscapeString(ovoCode)} .
    }
  }`;

  await update(insertData);

  return { uri: organizationUri, identifier: ovoCode, uuid: id };
};

const ensureOrganization = async function (ovoCode, graph) {
  const queryResult = await query(`
    PREFIX org: <http://www.w3.org/ns/org#>

    SELECT ?organization
    FROM <${graph}> {
        ?organization a org:Organization ;
            org:identifier ${sparqlEscapeString(ovoCode)} .
    }`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return { organizationUri: result.organization.value };
  } else {
    const organization = await insertNewOrganization(ovoCode, graph);
    return { organizationUri: organization.uri };
  }
};

export {
  ORG_GRAPH_URI,
  ovoCodeFromString,
  ensureOrganization
};
