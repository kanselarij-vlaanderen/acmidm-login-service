import { uuid, sparqlEscapeString, sparqlEscapeUri, sparqlEscapeDateTime } from 'mu';
import { updateSudo as update } from '@lblod/mu-auth-sudo';
import { USERS_GRAPH, RESOURCE_BASE_URI } from '../config';

const insertLoginActivity = async function(user) {
  const now = new Date();

  await update(`
  PREFIX prov: <http://www.w3.org/ns/prov#>
  PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>

  DELETE WHERE {
    GRAPH ${sparqlEscapeUri(USERS_GRAPH)} {
      ?s a ext:LoginActivity ;
         prov:wasAssociatedWith ${sparqlEscapeUri(user)} ;
         ?p ?o .
    }
  }`);

  const id = uuid();
  const loginActivity = `${RESOURCE_BASE_URI}/aanmeldingsactiviteit/${id}`;
  await update(`
  PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
  PREFIX prov: <http://www.w3.org/ns/prov#>
  PREFIX mu: <http://mu.semte.ch/vocabularies/core/>

  INSERT DATA {
    GRAPH ${sparqlEscapeUri(USERS_GRAPH)} {
      ${sparqlEscapeUri(loginActivity)} a ext:LoginActivity ;
        mu:uuid ${sparqlEscapeString(id)} ;
        prov:wasAssociatedWith ${sparqlEscapeUri(user)} ;
        prov:startedAtTime ${sparqlEscapeDateTime(now)} .
    }
  }`);
}

export {
  insertLoginActivity,
}
