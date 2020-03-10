import { uuid, sparqlEscapeUri, sparqlEscapeString } from 'mu';
import { querySudo as query, updateSudo as update } from './auth-sudo';

const organisationResourceBaseUri = 'https://data.vlaanderen.be/id/organisatie/';

const ovoCodeFromVoEmail = function (voEmail) {
  const match = voEmail.match(/OVO\d{6}/);
  return match ? match[0] : match;
};

const insertNewOrganisation = async function (ovoCode, graph) {
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

const addUserToOrganisation = async function (userUri, organizationUri, graph) {
  // For more info regarding compatibility of foaf's Agent (User) with dublin core's Agent (Organization member): http://xmlns.com/foaf/spec/#ext_dct_Agent
  const insertData = `
  PREFIX org: <http://www.w3.org/ns/org#>
  PREFIX foaf: <http://xmlns.com/foaf/0.1/>

  INSERT {
    GRAPH <${graph}> {
      ${sparqlEscapeUri(userUri)} org:memberOf ${sparqlEscapeString(organizationUri)} .
    }
  }
  WHERE {
    GRAPH <${graph}> {
      ${sparqlEscapeUri(userUri)} a foaf:Person .
      ${sparqlEscapeString(organizationUri)} a org:Organization .
    }
  }`;

  await update(insertData);
};

export {
  ovoCodeFromVoEmail,
  insertNewOrganisation,
};
