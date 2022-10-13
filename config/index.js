const RESOURCE_BASE_URI  = 'http://themis.vlaanderen.be';

const PUBLIC_GRAPH = 'http://mu.semte.ch/graphs/public';
const USERS_GRAPH = 'http://mu.semte.ch/graphs/system/users';
const SESSIONS_GRAPH = 'http://mu.semte.ch/graphs/sessions';

const ACCOUNT_SERVICE_HOMEPAGE = 'https://github.com/kanselarij-vlaanderen/acmidm-login-service';

const AUTH_USERID_CLAIM = process.env.MU_APPLICATION_AUTH_USERID_CLAIM || 'vo_id';
const AUTH_ACCOUNTID_CLAIM = process.env.MU_APPLICATION_AUTH_ACCOUNTID_CLAIM || 'sub';
const AUTH_ROLE_CLAIM = process.env.MU_APPLICATION_AUTH_ROLE_CLAIM || 'dkb_kaleidos_rol_3d';
const AUTH_ORG_CODE_CLAIM = 'vo_orgcode';
const AUTH_ORG_NAME_CLAIM = 'vo_orgnaam';
const AUTH_FIRST_NAME_CLAIM = 'given_name';
const AUTH_FAMILY_NAME_CLAIM = 'family_name';

const ACCESS_ALLOWED_STATUS_URI = 'http://themis.vlaanderen.be/id/concept/43ba4953-3484-4ec7-9741-6e709befc531';
const ACCESS_BLOCKED_STATUS_URI = 'http://themis.vlaanderen.be/id/concept/ffd0d21a-3beb-44c4-b3ff-06fe9561282a';

// Parse the role name from a claim coming from ACM/IDM
// E.g. KaleidosGebruiker-Kaleidos_Overheidsorganisatie:OVO000617
//      => Kaleidos_Overheidsorganisatie
const ROLE_CLAIM_REGEX = /^KaleidosGebruiker-(Kaleidos_[\d\w]*):/;
function parseRoleFromClaim(claim) {
  const match = claim?.match(ROLE_CLAIM_REGEX);
  return match ? match[1] : null;
}

export {
  RESOURCE_BASE_URI,
  USERS_GRAPH,
  SESSIONS_GRAPH,
  PUBLIC_GRAPH,
  ACCOUNT_SERVICE_HOMEPAGE,
  AUTH_USERID_CLAIM,
  AUTH_ACCOUNTID_CLAIM,
  AUTH_ROLE_CLAIM,
  AUTH_ORG_CODE_CLAIM,
  AUTH_ORG_NAME_CLAIM,
  AUTH_FIRST_NAME_CLAIM,
  AUTH_FAMILY_NAME_CLAIM,
  ACCESS_ALLOWED_STATUS_URI,
  ACCESS_BLOCKED_STATUS_URI,
  parseRoleFromClaim,
}
