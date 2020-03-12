import { uuid, sparqlEscapeUri, sparqlEscapeString } from 'mu';
import { querySudo as query, updateSudo as update } from './auth-sudo';
import { ovoCodeFromString, ensureOrganization } from './organization';

const allowNoRoleClaim = process.env.MU_APPLICATION_AUTH_ALLOW_NO_ROLE_CLAIM === 'true';
const defaultGroupUri = process.env.MU_APPLICATION_AUTH_DEFAULT_GROUP_URI;

const resourceBaseUri = process.env.MU_APPLICATION_RESOURCE_BASE_URI || 'http://data.lblod.info/';
const personResourceBaseUri = `${resourceBaseUri}id/persoon/`;
const identifierResourceBaseUri = `${resourceBaseUri}id/identificator/`;

const userIdClaim = process.env.MU_APPLICATION_AUTH_USERID_CLAIM || 'rrn';
const voEmailClaim = process.env.MU_APPLICATION_AUTH_VO_EMAIL_CLAIM || 'vo_email';
const phoneClaim = process.env.MU_APPLICATION_AUTH_VO_PHONE_CLAIM || 'phone';
const roleClaim = process.env.MU_APPLICATION_AUTH_ROLE_CLAIM;

const voEmailToEmail = function (voEmail) {
  // input format example: "test@example.com:OVO001827"
  return voEmail.split(':')[0];
};

const sanitizePhoneNumber = function (phone) {
  return phone.replace(/[/ .]/, '');
};

const emailToUri = function (email) {
  // "test@example.com" to "mailto:test@example.com"
  return `mailto:${email}`;
};

const uriToEmail = function (uri) {
  // "mailto:test@example.com" to "test@example.com"
  return uri.replace(/^mailto:/, '');
};

const phoneToUri = function (phone) {
  // "+3200000000" to "tel:+3200000000"
  return `tel:${phone}`;
};

const uriToPhone = function (uri) {
  // "tel:+3200000000" to "+3200000000"
  return uri.replace(/^tel:/, '');
};

const insertNewUser = async function (claims, graph) {
  const personId = uuid();
  const person = `${personResourceBaseUri}${personId}`;
  const identifierId = uuid();
  const identifier = `${identifierResourceBaseUri}${identifierId}`;

  let insertData = `
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX adms: <http://www.w3.org/ns/adms#>
    PREFIX skos: <http://www.w3.org/2004/02/skos/core#>

    INSERT DATA {
      GRAPH <${graph}> {
        ${sparqlEscapeUri(person)} a foaf:Person ;
           mu:uuid ${sparqlEscapeString(personId)} ;
           adms:identifier ${sparqlEscapeUri(identifier)} .
        ${sparqlEscapeUri(defaultGroupUri)} foaf:member ${sparqlEscapeUri(person)} .
        ${sparqlEscapeUri(identifier)} a adms:Identifier ;
           mu:uuid ${sparqlEscapeString(identifierId)} ;
           skos:notation ${sparqlEscapeString(claims[userIdClaim])} .
    `;

  if (claims.given_name) {
    insertData += `${sparqlEscapeUri(person)} foaf:firstName ${sparqlEscapeString(claims.given_name)} .\n`;
  }
  if (claims.family_name) {
    insertData += `${sparqlEscapeUri(person)} foaf:familyName ${sparqlEscapeString(claims.family_name)} .\n`;
  }
  if (claims[voEmailClaim]) {
    const emailUri = emailToUri(voEmailToEmail(claims[voEmailClaim]));
    insertData += `        ${sparqlEscapeUri(person)} foaf:mbox ${sparqlEscapeUri(emailUri)} .\n`;
  }
  if (claims[phoneClaim]) {
    const phoneUri = phoneToUri(sanitizePhoneNumber(claims[phoneClaim]));
    insertData += `        ${sparqlEscapeUri(person)} foaf:phone ${sparqlEscapeUri(phoneUri)} .\n`;
  }
  insertData += `
      }
    }
  `;

  await update(insertData);

  return { personUri: person, personId: personId };
};

const testIfPropertyUpToDate = function (result, claim) {
  if (result && claim) {
    return result === claim;
  } else if (!result && !claim) {
    return true;
  } else {
    return false;
  }
};

const checkIfFirstNameShouldbeUpdated = (result, claims) => !testIfPropertyUpToDate(result.firstName && result.firstName.value, claims.given_name);
const checkIfFamilyNameShouldbeUpdated = (result, claims) => !testIfPropertyUpToDate(result.familyName && result.familyName.value, claims.family_name);
const checkIfEmailShouldBeUpdated = (result, claims) => !testIfPropertyUpToDate(result.email && result.email.value && uriToEmail(result.email.value), claims[voEmailClaim] && voEmailToEmail(claims[voEmailClaim]));
const checkIfPhoneShouldbeUpdated = (result, claims) => !testIfPropertyUpToDate(result.phone && result.phone.value && uriToPhone(result.phone.value), claims[phoneClaim]);

const ensureUser = async function (claims, graph) {
  const userId = claims[userIdClaim];

  const queryResult = await query(`
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX adms: <http://www.w3.org/ns/adms#>
    PREFIX dcterms: <http://purl.org/dc/terms/>

    SELECT ?person ?personId ?email ?phone ?firstName ?familyName
    FROM <${graph}> {
      ?person a foaf:Person ;
            mu:uuid ?personId ;
            adms:identifier ?identifier .
      ?identifier skos:notation ${sparqlEscapeString(userId)} .
      OPTIONAL { ?person foaf:mbox ?email }
      OPTIONAL { ?person foaf:phone ?phone }
      OPTIONAL { ?person foaf:firstName ?firstName }
      OPTIONAL { ?person foaf:familyName ?familyName }
    }`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    const personUri = result.person.value;
    if (!(checkIfFirstNameShouldbeUpdated(result, claims) &&
      checkIfFamilyNameShouldbeUpdated(result, claims) &&
      checkIfEmailShouldBeUpdated(result, claims) &&
      checkIfPhoneShouldbeUpdated(result, claims))) {
      updateUserData(personUri, claims, graph); // Fire and forget, non-critical data must not hold up the authentication flow
    }
    return { personUri: personUri, personId: result.personId.value };
  } else {
    const { personUri, personId } = await insertNewUser(claims, graph);
    return { personUri, personId };
  }
};

const updateUserData = async function (personUri, claims, graph) {
  let updateQuery = `
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>

    DELETE {
      GRAPH <${graph}> {
        ${sparqlEscapeUri(personUri)} foaf:firstName ?firstName ;
          foaf:familyName ?lastName ;
          foaf:mbox ?email ;
          foaf:phone ?phone .
      }
    }
    INSERT {
      GRAPH <${graph}> {
    `;
  if (claims.given_name) {
    updateQuery += `        ${sparqlEscapeUri(personUri)} foaf:firstName ${sparqlEscapeString(claims.given_name)} .\n`;
  }
  if (claims.family_name) {
    updateQuery += `        ${sparqlEscapeUri(personUri)} foaf:familyName ${sparqlEscapeString(claims.family_name)} .\n`;
  }
  if (claims[voEmailClaim]) {
    const emailUri = emailToUri(voEmailToEmail(claims[voEmailClaim]));
    updateQuery += `        ${sparqlEscapeUri(personUri)} foaf:mbox ${sparqlEscapeUri(emailUri)} .\n`;
  }
  if (claims[phoneClaim]) {
    const phoneUri = phoneToUri(sanitizePhoneNumber(claims[phoneClaim]));
    updateQuery += `        ${sparqlEscapeUri(personUri)} foaf:phone ${sparqlEscapeUri(phoneUri)} .\n`;
  }
  updateQuery += `
      }
    }
    WHERE {
      GRAPH <${graph}> {
        ${sparqlEscapeUri(personUri)} a foaf:Person .
        OPTIONAL { ${sparqlEscapeUri(personUri)} foaf:firstName ?firstName . }
        OPTIONAL { ${sparqlEscapeUri(personUri)} foaf:familyName ?lastName . }
        OPTIONAL { ${sparqlEscapeUri(personUri)} foaf:mbox ?email . }
        OPTIONAL { ${sparqlEscapeUri(personUri)} foaf:phone ?phone . }
      }
    }`;

  await update(updateQuery);
};

const selectUserGroup = async function (accountUri, claims, roleClaim) {
  if ((claims[roleClaim] && claims[roleClaim].length > 0) ||
    allowNoRoleClaim) {
    const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX besluit: <http://data.vlaanderen.be/ns/besluit#>

    SELECT ?group ?groupId ?groupName
    WHERE {
      GRAPH <http://mu.semte.ch/graphs/public> {
          ?user foaf:account <${accountUri}> .
          ?group foaf:member ?user.
          ?group foaf:name ?groupName.
          ?group mu:uuid ?groupId.
      }
    }`);

    if (queryResult.results.bindings.length) {
      const result = queryResult.results.bindings[0];
      return { groupUri: result.group.value, groupId: result.groupId.value, groupName: result.groupName.value };
    }
  }
  return { groupUri: null, groupId: null, groupName: null };
};

const addUserToOrganization = async function (userUri, organizationUri, graph) {
  // For more info regarding compatibility of foaf's Agent (User) with dublin core's Agent (Organization member): http://xmlns.com/foaf/spec/#ext_dct_Agent
  const insertData = `
  PREFIX org: <http://www.w3.org/ns/org#>
  PREFIX foaf: <http://xmlns.com/foaf/0.1/>

  INSERT {
    GRAPH <${graph}> {
      ${sparqlEscapeUri(userUri)} org:memberOf ${sparqlEscapeUri(organizationUri)} .
    }
  }
  WHERE {
    GRAPH <${graph}> {
      ${sparqlEscapeUri(userUri)} a foaf:Person .
      ${sparqlEscapeUri(organizationUri)} a org:Organization .
    }
  }`;

  await update(insertData);
};

const ensureOrganisationForUser = async function (personUri, ovoCode, graph) {
  const queryString = `
    PREFIX org: <http://www.w3.org/ns/org#>

    SELECT ?organization
    FROM <${graph}> {
        ?organization a org:Organization ;
            org:identifier ${sparqlEscapeString(ovoCode)} .
        ${sparqlEscapeUri(personUri)} org:memberOf ?organization .
    }
  `;
  const queryResult = await query(queryString);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return { organizationUri: result.organization.value };
  } else {
    const organization = await ensureOrganization(ovoCode, graph);
    await addUserToOrganization(personUri, organization.organizationUri, graph);
  }
};

const ensureOrganisationsForUser = async function (personUri, claims, graph) {
  /*
   * Example role claim: "dkb_kaleidos_rol_3d":["KaleidosGebruiker-Kaleidos_Kanselarij:OVO001827"]
   */
  if (claims[roleClaim]) {
    for (const group of claims[roleClaim]) {
      const ovoCode = ovoCodeFromString(group);
      await ensureOrganisationForUser(personUri, ovoCode, graph);
    }
  }
};

export {
  ensureUser,
  selectUserGroup,
  ensureOrganisationsForUser
};
