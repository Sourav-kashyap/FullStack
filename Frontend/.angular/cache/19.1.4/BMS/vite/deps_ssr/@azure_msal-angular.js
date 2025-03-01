import { createRequire } from 'module';const require = createRequire(import.meta.url);
import "./chunk-VHNPSFJR.js";
import {
  Router
} from "./chunk-PK7IZZUC.js";
import "./chunk-LTXPTTZ6.js";
import "./chunk-ZC4MJQ2R.js";
import {
  CommonModule,
  DOCUMENT,
  Location
} from "./chunk-OQPWJ5H2.js";
import {
  Component,
  Inject,
  Injectable,
  InjectionToken,
  NgModule,
  Optional,
  setClassMetadata,
  ɵɵdefineComponent,
  ɵɵdefineInjectable,
  ɵɵdefineInjector,
  ɵɵdefineNgModule,
  ɵɵdirectiveInject,
  ɵɵinject
} from "./chunk-JFI7PHUG.js";
import {
  require_cjs
} from "./chunk-DIUVRKIA.js";
import {
  require_operators
} from "./chunk-YKQGHLWV.js";
import "./chunk-7TTYJDY5.js";
import {
  __async,
  __export,
  __spreadProps,
  __spreadValues,
  __toESM
} from "./chunk-ANGF2IQY.js";

// node_modules/@azure/msal-browser/dist/utils/BrowserUtils.mjs
var BrowserUtils_exports = {};
__export(BrowserUtils_exports, {
  blockAPICallsBeforeInitialize: () => blockAPICallsBeforeInitialize,
  blockAcquireTokenInPopups: () => blockAcquireTokenInPopups,
  blockNonBrowserEnvironment: () => blockNonBrowserEnvironment,
  blockRedirectInIframe: () => blockRedirectInIframe,
  blockReloadInHiddenIframes: () => blockReloadInHiddenIframes,
  clearHash: () => clearHash,
  createGuid: () => createGuid,
  getCurrentUri: () => getCurrentUri,
  getHomepage: () => getHomepage,
  invoke: () => invoke,
  invokeAsync: () => invokeAsync,
  isInIframe: () => isInIframe,
  isInPopup: () => isInPopup,
  preconnect: () => preconnect,
  preflightCheck: () => preflightCheck,
  redirectPreflightCheck: () => redirectPreflightCheck,
  replaceHash: () => replaceHash
});

// node_modules/@azure/msal-common/dist/utils/Constants.mjs
var Constants = {
  LIBRARY_NAME: "MSAL.JS",
  SKU: "msal.js.common",
  // Prefix for all library cache entries
  CACHE_PREFIX: "msal",
  // default authority
  DEFAULT_AUTHORITY: "https://login.microsoftonline.com/common/",
  DEFAULT_AUTHORITY_HOST: "login.microsoftonline.com",
  DEFAULT_COMMON_TENANT: "common",
  // ADFS String
  ADFS: "adfs",
  DSTS: "dstsv2",
  // Default AAD Instance Discovery Endpoint
  AAD_INSTANCE_DISCOVERY_ENDPT: "https://login.microsoftonline.com/common/discovery/instance?api-version=1.1&authorization_endpoint=",
  // CIAM URL
  CIAM_AUTH_URL: ".ciamlogin.com",
  AAD_TENANT_DOMAIN_SUFFIX: ".onmicrosoft.com",
  // Resource delimiter - used for certain cache entries
  RESOURCE_DELIM: "|",
  // Placeholder for non-existent account ids/objects
  NO_ACCOUNT: "NO_ACCOUNT",
  // Claims
  CLAIMS: "claims",
  // Consumer UTID
  CONSUMER_UTID: "9188040d-6c67-4c5b-b112-36a304b66dad",
  // Default scopes
  OPENID_SCOPE: "openid",
  PROFILE_SCOPE: "profile",
  OFFLINE_ACCESS_SCOPE: "offline_access",
  EMAIL_SCOPE: "email",
  // Default response type for authorization code flow
  CODE_RESPONSE_TYPE: "code",
  CODE_GRANT_TYPE: "authorization_code",
  RT_GRANT_TYPE: "refresh_token",
  FRAGMENT_RESPONSE_MODE: "fragment",
  S256_CODE_CHALLENGE_METHOD: "S256",
  URL_FORM_CONTENT_TYPE: "application/x-www-form-urlencoded;charset=utf-8",
  AUTHORIZATION_PENDING: "authorization_pending",
  NOT_DEFINED: "not_defined",
  EMPTY_STRING: "",
  NOT_APPLICABLE: "N/A",
  NOT_AVAILABLE: "Not Available",
  FORWARD_SLASH: "/",
  IMDS_ENDPOINT: "http://169.254.169.254/metadata/instance/compute/location",
  IMDS_VERSION: "2020-06-01",
  IMDS_TIMEOUT: 2e3,
  AZURE_REGION_AUTO_DISCOVER_FLAG: "TryAutoDetect",
  REGIONAL_AUTH_PUBLIC_CLOUD_SUFFIX: "login.microsoft.com",
  KNOWN_PUBLIC_CLOUDS: ["login.microsoftonline.com", "login.windows.net", "login.microsoft.com", "sts.windows.net"],
  TOKEN_RESPONSE_TYPE: "token",
  ID_TOKEN_RESPONSE_TYPE: "id_token",
  SHR_NONCE_VALIDITY: 240,
  INVALID_INSTANCE: "invalid_instance"
};
var OIDC_DEFAULT_SCOPES = [Constants.OPENID_SCOPE, Constants.PROFILE_SCOPE, Constants.OFFLINE_ACCESS_SCOPE];
var OIDC_SCOPES = [...OIDC_DEFAULT_SCOPES, Constants.EMAIL_SCOPE];
var AADAuthorityConstants = {
  COMMON: "common",
  ORGANIZATIONS: "organizations",
  CONSUMERS: "consumers"
};
var ServerResponseType = {
  QUERY: "query",
  FRAGMENT: "fragment"
};
var ResponseMode = __spreadProps(__spreadValues({}, ServerResponseType), {
  FORM_POST: "form_post"
});
var AUTHORITY_METADATA_CONSTANTS = {
  CACHE_KEY: "authority-metadata",
  REFRESH_TIME_SECONDS: 3600 * 24
  // 24 Hours
};
var AuthorityMetadataSource = {
  CONFIG: "config",
  CACHE: "cache",
  NETWORK: "network",
  HARDCODED_VALUES: "hardcoded_values"
};
var ResponseCodes = {
  httpSuccess: 200,
  httpBadRequest: 400
};
var RegionDiscoverySources = {
  FAILED_AUTO_DETECTION: "1",
  INTERNAL_CACHE: "2",
  ENVIRONMENT_VARIABLE: "3",
  IMDS: "4"
};
var RegionDiscoveryOutcomes = {
  CONFIGURED_MATCHES_DETECTED: "1",
  CONFIGURED_NO_AUTO_DETECTION: "2",
  CONFIGURED_NOT_DETECTED: "3",
  AUTO_DETECTION_REQUESTED_SUCCESSFUL: "4",
  AUTO_DETECTION_REQUESTED_FAILED: "5"
};
var JsonWebTokenTypes = {
  Jwt: "JWT",
  Jwk: "JWK",
  Pop: "pop"
};
var DEFAULT_TOKEN_RENEWAL_OFFSET_SEC = 300;

// node_modules/@azure/msal-common/dist/error/AuthErrorCodes.mjs
var unexpectedError = "unexpected_error";
var postRequestFailed = "post_request_failed";

// node_modules/@azure/msal-common/dist/error/AuthError.mjs
var AuthErrorMessages = {
  [unexpectedError]: "Unexpected error in authentication.",
  [postRequestFailed]: "Post request failed from the network, could be a 4xx/5xx or a network unavailability. Please check the exact error code for details."
};
var AuthErrorMessage = {
  unexpectedError: {
    code: unexpectedError,
    desc: AuthErrorMessages[unexpectedError]
  },
  postRequestFailed: {
    code: postRequestFailed,
    desc: AuthErrorMessages[postRequestFailed]
  }
};
var AuthError = class _AuthError extends Error {
  constructor(errorCode, errorMessage, suberror) {
    const errorString = errorMessage ? `${errorCode}: ${errorMessage}` : errorCode;
    super(errorString);
    Object.setPrototypeOf(this, _AuthError.prototype);
    this.errorCode = errorCode || Constants.EMPTY_STRING;
    this.errorMessage = errorMessage || Constants.EMPTY_STRING;
    this.subError = suberror || Constants.EMPTY_STRING;
    this.name = "AuthError";
  }
  setCorrelationId(correlationId) {
    this.correlationId = correlationId;
  }
};

// node_modules/@azure/msal-common/dist/error/ClientAuthErrorCodes.mjs
var clientInfoDecodingError = "client_info_decoding_error";
var clientInfoEmptyError = "client_info_empty_error";
var tokenParsingError = "token_parsing_error";
var nullOrEmptyToken = "null_or_empty_token";
var endpointResolutionError = "endpoints_resolution_error";
var networkError = "network_error";
var openIdConfigError = "openid_config_error";
var hashNotDeserialized = "hash_not_deserialized";
var invalidState = "invalid_state";
var stateMismatch = "state_mismatch";
var stateNotFound = "state_not_found";
var nonceMismatch = "nonce_mismatch";
var authTimeNotFound = "auth_time_not_found";
var maxAgeTranspired = "max_age_transpired";
var multipleMatchingTokens = "multiple_matching_tokens";
var multipleMatchingAccounts = "multiple_matching_accounts";
var multipleMatchingAppMetadata = "multiple_matching_appMetadata";
var requestCannotBeMade = "request_cannot_be_made";
var cannotRemoveEmptyScope = "cannot_remove_empty_scope";
var cannotAppendScopeSet = "cannot_append_scopeset";
var emptyInputScopeSet = "empty_input_scopeset";
var deviceCodePollingCancelled = "device_code_polling_cancelled";
var deviceCodeExpired = "device_code_expired";
var deviceCodeUnknownError = "device_code_unknown_error";
var noAccountInSilentRequest = "no_account_in_silent_request";
var invalidCacheRecord = "invalid_cache_record";
var invalidCacheEnvironment = "invalid_cache_environment";
var noAccountFound = "no_account_found";
var noCryptoObject = "no_crypto_object";
var unexpectedCredentialType = "unexpected_credential_type";
var invalidAssertion = "invalid_assertion";
var invalidClientCredential = "invalid_client_credential";
var tokenRefreshRequired = "token_refresh_required";
var userTimeoutReached = "user_timeout_reached";
var tokenClaimsCnfRequiredForSignedJwt = "token_claims_cnf_required_for_signedjwt";
var authorizationCodeMissingFromServerResponse = "authorization_code_missing_from_server_response";
var bindingKeyNotRemoved = "binding_key_not_removed";
var endSessionEndpointNotSupported = "end_session_endpoint_not_supported";
var keyIdMissing = "key_id_missing";
var noNetworkConnectivity = "no_network_connectivity";
var userCanceled = "user_canceled";
var missingTenantIdError = "missing_tenant_id_error";
var methodNotImplemented = "method_not_implemented";
var nestedAppAuthBridgeDisabled = "nested_app_auth_bridge_disabled";

// node_modules/@azure/msal-common/dist/error/ClientAuthError.mjs
var ClientAuthErrorMessages = {
  [clientInfoDecodingError]: "The client info could not be parsed/decoded correctly",
  [clientInfoEmptyError]: "The client info was empty",
  [tokenParsingError]: "Token cannot be parsed",
  [nullOrEmptyToken]: "The token is null or empty",
  [endpointResolutionError]: "Endpoints cannot be resolved",
  [networkError]: "Network request failed",
  [openIdConfigError]: "Could not retrieve endpoints. Check your authority and verify the .well-known/openid-configuration endpoint returns the required endpoints.",
  [hashNotDeserialized]: "The hash parameters could not be deserialized",
  [invalidState]: "State was not the expected format",
  [stateMismatch]: "State mismatch error",
  [stateNotFound]: "State not found",
  [nonceMismatch]: "Nonce mismatch error",
  [authTimeNotFound]: "Max Age was requested and the ID token is missing the auth_time variable. auth_time is an optional claim and is not enabled by default - it must be enabled. See https://aka.ms/msaljs/optional-claims for more information.",
  [maxAgeTranspired]: "Max Age is set to 0, or too much time has elapsed since the last end-user authentication.",
  [multipleMatchingTokens]: "The cache contains multiple tokens satisfying the requirements. Call AcquireToken again providing more requirements such as authority or account.",
  [multipleMatchingAccounts]: "The cache contains multiple accounts satisfying the given parameters. Please pass more info to obtain the correct account",
  [multipleMatchingAppMetadata]: "The cache contains multiple appMetadata satisfying the given parameters. Please pass more info to obtain the correct appMetadata",
  [requestCannotBeMade]: "Token request cannot be made without authorization code or refresh token.",
  [cannotRemoveEmptyScope]: "Cannot remove null or empty scope from ScopeSet",
  [cannotAppendScopeSet]: "Cannot append ScopeSet",
  [emptyInputScopeSet]: "Empty input ScopeSet cannot be processed",
  [deviceCodePollingCancelled]: "Caller has cancelled token endpoint polling during device code flow by setting DeviceCodeRequest.cancel = true.",
  [deviceCodeExpired]: "Device code is expired.",
  [deviceCodeUnknownError]: "Device code stopped polling for unknown reasons.",
  [noAccountInSilentRequest]: "Please pass an account object, silent flow is not supported without account information",
  [invalidCacheRecord]: "Cache record object was null or undefined.",
  [invalidCacheEnvironment]: "Invalid environment when attempting to create cache entry",
  [noAccountFound]: "No account found in cache for given key.",
  [noCryptoObject]: "No crypto object detected.",
  [unexpectedCredentialType]: "Unexpected credential type.",
  [invalidAssertion]: "Client assertion must meet requirements described in https://tools.ietf.org/html/rfc7515",
  [invalidClientCredential]: "Client credential (secret, certificate, or assertion) must not be empty when creating a confidential client. An application should at most have one credential",
  [tokenRefreshRequired]: "Cannot return token from cache because it must be refreshed. This may be due to one of the following reasons: forceRefresh parameter is set to true, claims have been requested, there is no cached access token or it is expired.",
  [userTimeoutReached]: "User defined timeout for device code polling reached",
  [tokenClaimsCnfRequiredForSignedJwt]: "Cannot generate a POP jwt if the token_claims are not populated",
  [authorizationCodeMissingFromServerResponse]: "Server response does not contain an authorization code to proceed",
  [bindingKeyNotRemoved]: "Could not remove the credential's binding key from storage.",
  [endSessionEndpointNotSupported]: "The provided authority does not support logout",
  [keyIdMissing]: "A keyId value is missing from the requested bound token's cache record and is required to match the token to it's stored binding key.",
  [noNetworkConnectivity]: "No network connectivity. Check your internet connection.",
  [userCanceled]: "User cancelled the flow.",
  [missingTenantIdError]: "A tenant id - not common, organizations, or consumers - must be specified when using the client_credentials flow.",
  [methodNotImplemented]: "This method has not been implemented",
  [nestedAppAuthBridgeDisabled]: "The nested app auth bridge is disabled"
};
var ClientAuthErrorMessage = {
  clientInfoDecodingError: {
    code: clientInfoDecodingError,
    desc: ClientAuthErrorMessages[clientInfoDecodingError]
  },
  clientInfoEmptyError: {
    code: clientInfoEmptyError,
    desc: ClientAuthErrorMessages[clientInfoEmptyError]
  },
  tokenParsingError: {
    code: tokenParsingError,
    desc: ClientAuthErrorMessages[tokenParsingError]
  },
  nullOrEmptyToken: {
    code: nullOrEmptyToken,
    desc: ClientAuthErrorMessages[nullOrEmptyToken]
  },
  endpointResolutionError: {
    code: endpointResolutionError,
    desc: ClientAuthErrorMessages[endpointResolutionError]
  },
  networkError: {
    code: networkError,
    desc: ClientAuthErrorMessages[networkError]
  },
  unableToGetOpenidConfigError: {
    code: openIdConfigError,
    desc: ClientAuthErrorMessages[openIdConfigError]
  },
  hashNotDeserialized: {
    code: hashNotDeserialized,
    desc: ClientAuthErrorMessages[hashNotDeserialized]
  },
  invalidStateError: {
    code: invalidState,
    desc: ClientAuthErrorMessages[invalidState]
  },
  stateMismatchError: {
    code: stateMismatch,
    desc: ClientAuthErrorMessages[stateMismatch]
  },
  stateNotFoundError: {
    code: stateNotFound,
    desc: ClientAuthErrorMessages[stateNotFound]
  },
  nonceMismatchError: {
    code: nonceMismatch,
    desc: ClientAuthErrorMessages[nonceMismatch]
  },
  authTimeNotFoundError: {
    code: authTimeNotFound,
    desc: ClientAuthErrorMessages[authTimeNotFound]
  },
  maxAgeTranspired: {
    code: maxAgeTranspired,
    desc: ClientAuthErrorMessages[maxAgeTranspired]
  },
  multipleMatchingTokens: {
    code: multipleMatchingTokens,
    desc: ClientAuthErrorMessages[multipleMatchingTokens]
  },
  multipleMatchingAccounts: {
    code: multipleMatchingAccounts,
    desc: ClientAuthErrorMessages[multipleMatchingAccounts]
  },
  multipleMatchingAppMetadata: {
    code: multipleMatchingAppMetadata,
    desc: ClientAuthErrorMessages[multipleMatchingAppMetadata]
  },
  tokenRequestCannotBeMade: {
    code: requestCannotBeMade,
    desc: ClientAuthErrorMessages[requestCannotBeMade]
  },
  removeEmptyScopeError: {
    code: cannotRemoveEmptyScope,
    desc: ClientAuthErrorMessages[cannotRemoveEmptyScope]
  },
  appendScopeSetError: {
    code: cannotAppendScopeSet,
    desc: ClientAuthErrorMessages[cannotAppendScopeSet]
  },
  emptyInputScopeSetError: {
    code: emptyInputScopeSet,
    desc: ClientAuthErrorMessages[emptyInputScopeSet]
  },
  DeviceCodePollingCancelled: {
    code: deviceCodePollingCancelled,
    desc: ClientAuthErrorMessages[deviceCodePollingCancelled]
  },
  DeviceCodeExpired: {
    code: deviceCodeExpired,
    desc: ClientAuthErrorMessages[deviceCodeExpired]
  },
  DeviceCodeUnknownError: {
    code: deviceCodeUnknownError,
    desc: ClientAuthErrorMessages[deviceCodeUnknownError]
  },
  NoAccountInSilentRequest: {
    code: noAccountInSilentRequest,
    desc: ClientAuthErrorMessages[noAccountInSilentRequest]
  },
  invalidCacheRecord: {
    code: invalidCacheRecord,
    desc: ClientAuthErrorMessages[invalidCacheRecord]
  },
  invalidCacheEnvironment: {
    code: invalidCacheEnvironment,
    desc: ClientAuthErrorMessages[invalidCacheEnvironment]
  },
  noAccountFound: {
    code: noAccountFound,
    desc: ClientAuthErrorMessages[noAccountFound]
  },
  noCryptoObj: {
    code: noCryptoObject,
    desc: ClientAuthErrorMessages[noCryptoObject]
  },
  unexpectedCredentialType: {
    code: unexpectedCredentialType,
    desc: ClientAuthErrorMessages[unexpectedCredentialType]
  },
  invalidAssertion: {
    code: invalidAssertion,
    desc: ClientAuthErrorMessages[invalidAssertion]
  },
  invalidClientCredential: {
    code: invalidClientCredential,
    desc: ClientAuthErrorMessages[invalidClientCredential]
  },
  tokenRefreshRequired: {
    code: tokenRefreshRequired,
    desc: ClientAuthErrorMessages[tokenRefreshRequired]
  },
  userTimeoutReached: {
    code: userTimeoutReached,
    desc: ClientAuthErrorMessages[userTimeoutReached]
  },
  tokenClaimsRequired: {
    code: tokenClaimsCnfRequiredForSignedJwt,
    desc: ClientAuthErrorMessages[tokenClaimsCnfRequiredForSignedJwt]
  },
  noAuthorizationCodeFromServer: {
    code: authorizationCodeMissingFromServerResponse,
    desc: ClientAuthErrorMessages[authorizationCodeMissingFromServerResponse]
  },
  bindingKeyNotRemovedError: {
    code: bindingKeyNotRemoved,
    desc: ClientAuthErrorMessages[bindingKeyNotRemoved]
  },
  logoutNotSupported: {
    code: endSessionEndpointNotSupported,
    desc: ClientAuthErrorMessages[endSessionEndpointNotSupported]
  },
  keyIdMissing: {
    code: keyIdMissing,
    desc: ClientAuthErrorMessages[keyIdMissing]
  },
  noNetworkConnectivity: {
    code: noNetworkConnectivity,
    desc: ClientAuthErrorMessages[noNetworkConnectivity]
  },
  userCanceledError: {
    code: userCanceled,
    desc: ClientAuthErrorMessages[userCanceled]
  },
  missingTenantIdError: {
    code: missingTenantIdError,
    desc: ClientAuthErrorMessages[missingTenantIdError]
  },
  nestedAppAuthBridgeDisabled: {
    code: nestedAppAuthBridgeDisabled,
    desc: ClientAuthErrorMessages[nestedAppAuthBridgeDisabled]
  }
};
var ClientAuthError = class _ClientAuthError extends AuthError {
  constructor(errorCode, additionalMessage) {
    super(errorCode, additionalMessage ? `${ClientAuthErrorMessages[errorCode]}: ${additionalMessage}` : ClientAuthErrorMessages[errorCode]);
    this.name = "ClientAuthError";
    Object.setPrototypeOf(this, _ClientAuthError.prototype);
  }
};
function createClientAuthError(errorCode, additionalMessage) {
  return new ClientAuthError(errorCode, additionalMessage);
}

// node_modules/@azure/msal-common/dist/logger/Logger.mjs
var LogLevel;
(function(LogLevel2) {
  LogLevel2[LogLevel2["Error"] = 0] = "Error";
  LogLevel2[LogLevel2["Warning"] = 1] = "Warning";
  LogLevel2[LogLevel2["Info"] = 2] = "Info";
  LogLevel2[LogLevel2["Verbose"] = 3] = "Verbose";
  LogLevel2[LogLevel2["Trace"] = 4] = "Trace";
})(LogLevel || (LogLevel = {}));
var Logger = class _Logger {
  constructor(loggerOptions, packageName, packageVersion) {
    this.level = LogLevel.Info;
    const defaultLoggerCallback = () => {
      return;
    };
    const setLoggerOptions = loggerOptions || _Logger.createDefaultLoggerOptions();
    this.localCallback = setLoggerOptions.loggerCallback || defaultLoggerCallback;
    this.piiLoggingEnabled = setLoggerOptions.piiLoggingEnabled || false;
    this.level = typeof setLoggerOptions.logLevel === "number" ? setLoggerOptions.logLevel : LogLevel.Info;
    this.correlationId = setLoggerOptions.correlationId || Constants.EMPTY_STRING;
    this.packageName = packageName || Constants.EMPTY_STRING;
    this.packageVersion = packageVersion || Constants.EMPTY_STRING;
  }
  static createDefaultLoggerOptions() {
    return {
      loggerCallback: () => {
      },
      piiLoggingEnabled: false,
      logLevel: LogLevel.Info
    };
  }
  /**
   * Create new Logger with existing configurations.
   */
  clone(packageName, packageVersion, correlationId) {
    return new _Logger({
      loggerCallback: this.localCallback,
      piiLoggingEnabled: this.piiLoggingEnabled,
      logLevel: this.level,
      correlationId: correlationId || this.correlationId
    }, packageName, packageVersion);
  }
  /**
   * Log message with required options.
   */
  logMessage(logMessage, options) {
    if (options.logLevel > this.level || !this.piiLoggingEnabled && options.containsPii) {
      return;
    }
    const timestamp = (/* @__PURE__ */ new Date()).toUTCString();
    const logHeader = `[${timestamp}] : [${options.correlationId || this.correlationId || ""}]`;
    const log = `${logHeader} : ${this.packageName}@${this.packageVersion} : ${LogLevel[options.logLevel]} - ${logMessage}`;
    this.executeCallback(options.logLevel, log, options.containsPii || false);
  }
  /**
   * Execute callback with message.
   */
  executeCallback(level, message, containsPii) {
    if (this.localCallback) {
      this.localCallback(level, message, containsPii);
    }
  }
  /**
   * Logs error messages.
   */
  error(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Error,
      containsPii: false,
      correlationId: correlationId || Constants.EMPTY_STRING
    });
  }
  /**
   * Logs error messages with PII.
   */
  errorPii(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Error,
      containsPii: true,
      correlationId: correlationId || Constants.EMPTY_STRING
    });
  }
  /**
   * Logs warning messages.
   */
  warning(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Warning,
      containsPii: false,
      correlationId: correlationId || Constants.EMPTY_STRING
    });
  }
  /**
   * Logs warning messages with PII.
   */
  warningPii(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Warning,
      containsPii: true,
      correlationId: correlationId || Constants.EMPTY_STRING
    });
  }
  /**
   * Logs info messages.
   */
  info(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Info,
      containsPii: false,
      correlationId: correlationId || Constants.EMPTY_STRING
    });
  }
  /**
   * Logs info messages with PII.
   */
  infoPii(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Info,
      containsPii: true,
      correlationId: correlationId || Constants.EMPTY_STRING
    });
  }
  /**
   * Logs verbose messages.
   */
  verbose(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Verbose,
      containsPii: false,
      correlationId: correlationId || Constants.EMPTY_STRING
    });
  }
  /**
   * Logs verbose messages with PII.
   */
  verbosePii(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Verbose,
      containsPii: true,
      correlationId: correlationId || Constants.EMPTY_STRING
    });
  }
  /**
   * Logs trace messages.
   */
  trace(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Trace,
      containsPii: false,
      correlationId: correlationId || Constants.EMPTY_STRING
    });
  }
  /**
   * Logs trace messages with PII.
   */
  tracePii(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Trace,
      containsPii: true,
      correlationId: correlationId || Constants.EMPTY_STRING
    });
  }
  /**
   * Returns whether PII Logging is enabled or not.
   */
  isPiiLoggingEnabled() {
    return this.piiLoggingEnabled || false;
  }
};

// node_modules/@azure/msal-common/dist/packageMetadata.mjs
var version = "15.2.0";

// node_modules/@azure/msal-common/dist/authority/AuthorityOptions.mjs
var AzureCloudInstance = {
  // AzureCloudInstance is not specified.
  None: "none",
  // Microsoft Azure public cloud
  AzurePublic: "https://login.microsoftonline.com",
  // Microsoft PPE
  AzurePpe: "https://login.windows-ppe.net",
  // Microsoft Chinese national/regional cloud
  AzureChina: "https://login.chinacloudapi.cn",
  // Microsoft German national/regional cloud ("Black Forest")
  AzureGermany: "https://login.microsoftonline.de",
  // US Government cloud
  AzureUsGovernment: "https://login.microsoftonline.us"
};

// node_modules/@azure/msal-common/dist/utils/TimeUtils.mjs
function nowSeconds() {
  return Math.round((/* @__PURE__ */ new Date()).getTime() / 1e3);
}

// node_modules/@azure/msal-common/dist/cache/utils/CacheHelpers.mjs
function generateAuthorityMetadataExpiresAt() {
  return nowSeconds() + AUTHORITY_METADATA_CONSTANTS.REFRESH_TIME_SECONDS;
}
function updateAuthorityEndpointMetadata(authorityMetadata, updatedValues, fromNetwork) {
  authorityMetadata.authorization_endpoint = updatedValues.authorization_endpoint;
  authorityMetadata.token_endpoint = updatedValues.token_endpoint;
  authorityMetadata.end_session_endpoint = updatedValues.end_session_endpoint;
  authorityMetadata.issuer = updatedValues.issuer;
  authorityMetadata.endpointsFromNetwork = fromNetwork;
  authorityMetadata.jwks_uri = updatedValues.jwks_uri;
}
function updateCloudDiscoveryMetadata(authorityMetadata, updatedValues, fromNetwork) {
  authorityMetadata.aliases = updatedValues.aliases;
  authorityMetadata.preferred_cache = updatedValues.preferred_cache;
  authorityMetadata.preferred_network = updatedValues.preferred_network;
  authorityMetadata.aliasesFromNetwork = fromNetwork;
}
function isAuthorityMetadataExpired(metadata) {
  return metadata.expiresAt <= nowSeconds();
}

// node_modules/@azure/msal-common/dist/error/ClientConfigurationErrorCodes.mjs
var ClientConfigurationErrorCodes_exports = {};
__export(ClientConfigurationErrorCodes_exports, {
  authorityMismatch: () => authorityMismatch,
  authorityUriInsecure: () => authorityUriInsecure,
  cannotAllowPlatformBroker: () => cannotAllowPlatformBroker,
  cannotSetOIDCOptions: () => cannotSetOIDCOptions,
  claimsRequestParsingError: () => claimsRequestParsingError,
  emptyInputScopesError: () => emptyInputScopesError,
  invalidAuthenticationHeader: () => invalidAuthenticationHeader,
  invalidAuthorityMetadata: () => invalidAuthorityMetadata,
  invalidClaims: () => invalidClaims,
  invalidCloudDiscoveryMetadata: () => invalidCloudDiscoveryMetadata,
  invalidCodeChallengeMethod: () => invalidCodeChallengeMethod,
  invalidPromptValue: () => invalidPromptValue,
  logoutRequestEmpty: () => logoutRequestEmpty,
  missingNonceAuthenticationHeader: () => missingNonceAuthenticationHeader,
  missingSshJwk: () => missingSshJwk,
  missingSshKid: () => missingSshKid,
  pkceParamsMissing: () => pkceParamsMissing,
  redirectUriEmpty: () => redirectUriEmpty,
  tokenRequestEmpty: () => tokenRequestEmpty,
  untrustedAuthority: () => untrustedAuthority,
  urlEmptyError: () => urlEmptyError,
  urlParseError: () => urlParseError
});
var redirectUriEmpty = "redirect_uri_empty";
var claimsRequestParsingError = "claims_request_parsing_error";
var authorityUriInsecure = "authority_uri_insecure";
var urlParseError = "url_parse_error";
var urlEmptyError = "empty_url_error";
var emptyInputScopesError = "empty_input_scopes_error";
var invalidPromptValue = "invalid_prompt_value";
var invalidClaims = "invalid_claims";
var tokenRequestEmpty = "token_request_empty";
var logoutRequestEmpty = "logout_request_empty";
var invalidCodeChallengeMethod = "invalid_code_challenge_method";
var pkceParamsMissing = "pkce_params_missing";
var invalidCloudDiscoveryMetadata = "invalid_cloud_discovery_metadata";
var invalidAuthorityMetadata = "invalid_authority_metadata";
var untrustedAuthority = "untrusted_authority";
var missingSshJwk = "missing_ssh_jwk";
var missingSshKid = "missing_ssh_kid";
var missingNonceAuthenticationHeader = "missing_nonce_authentication_header";
var invalidAuthenticationHeader = "invalid_authentication_header";
var cannotSetOIDCOptions = "cannot_set_OIDCOptions";
var cannotAllowPlatformBroker = "cannot_allow_platform_broker";
var authorityMismatch = "authority_mismatch";

// node_modules/@azure/msal-common/dist/error/ClientConfigurationError.mjs
var ClientConfigurationErrorMessages = {
  [redirectUriEmpty]: "A redirect URI is required for all calls, and none has been set.",
  [claimsRequestParsingError]: "Could not parse the given claims request object.",
  [authorityUriInsecure]: "Authority URIs must use https.  Please see here for valid authority configuration options: https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-js-initializing-client-applications#configuration-options",
  [urlParseError]: "URL could not be parsed into appropriate segments.",
  [urlEmptyError]: "URL was empty or null.",
  [emptyInputScopesError]: "Scopes cannot be passed as null, undefined or empty array because they are required to obtain an access token.",
  [invalidPromptValue]: "Please see here for valid configuration options: https://azuread.github.io/microsoft-authentication-library-for-js/ref/modules/_azure_msal_common.html#commonauthorizationurlrequest",
  [invalidClaims]: "Given claims parameter must be a stringified JSON object.",
  [tokenRequestEmpty]: "Token request was empty and not found in cache.",
  [logoutRequestEmpty]: "The logout request was null or undefined.",
  [invalidCodeChallengeMethod]: 'code_challenge_method passed is invalid. Valid values are "plain" and "S256".',
  [pkceParamsMissing]: "Both params: code_challenge and code_challenge_method are to be passed if to be sent in the request",
  [invalidCloudDiscoveryMetadata]: "Invalid cloudDiscoveryMetadata provided. Must be a stringified JSON object containing tenant_discovery_endpoint and metadata fields",
  [invalidAuthorityMetadata]: "Invalid authorityMetadata provided. Must by a stringified JSON object containing authorization_endpoint, token_endpoint, issuer fields.",
  [untrustedAuthority]: "The provided authority is not a trusted authority. Please include this authority in the knownAuthorities config parameter.",
  [missingSshJwk]: "Missing sshJwk in SSH certificate request. A stringified JSON Web Key is required when using the SSH authentication scheme.",
  [missingSshKid]: "Missing sshKid in SSH certificate request. A string that uniquely identifies the public SSH key is required when using the SSH authentication scheme.",
  [missingNonceAuthenticationHeader]: "Unable to find an authentication header containing server nonce. Either the Authentication-Info or WWW-Authenticate headers must be present in order to obtain a server nonce.",
  [invalidAuthenticationHeader]: "Invalid authentication header provided",
  [cannotSetOIDCOptions]: "Cannot set OIDCOptions parameter. Please change the protocol mode to OIDC or use a non-Microsoft authority.",
  [cannotAllowPlatformBroker]: "Cannot set allowPlatformBroker parameter to true when not in AAD protocol mode.",
  [authorityMismatch]: "Authority mismatch error. Authority provided in login request or PublicClientApplication config does not match the environment of the provided account. Please use a matching account or make an interactive request to login to this authority."
};
var ClientConfigurationErrorMessage = {
  redirectUriNotSet: {
    code: redirectUriEmpty,
    desc: ClientConfigurationErrorMessages[redirectUriEmpty]
  },
  claimsRequestParsingError: {
    code: claimsRequestParsingError,
    desc: ClientConfigurationErrorMessages[claimsRequestParsingError]
  },
  authorityUriInsecure: {
    code: authorityUriInsecure,
    desc: ClientConfigurationErrorMessages[authorityUriInsecure]
  },
  urlParseError: {
    code: urlParseError,
    desc: ClientConfigurationErrorMessages[urlParseError]
  },
  urlEmptyError: {
    code: urlEmptyError,
    desc: ClientConfigurationErrorMessages[urlEmptyError]
  },
  emptyScopesError: {
    code: emptyInputScopesError,
    desc: ClientConfigurationErrorMessages[emptyInputScopesError]
  },
  invalidPrompt: {
    code: invalidPromptValue,
    desc: ClientConfigurationErrorMessages[invalidPromptValue]
  },
  invalidClaimsRequest: {
    code: invalidClaims,
    desc: ClientConfigurationErrorMessages[invalidClaims]
  },
  tokenRequestEmptyError: {
    code: tokenRequestEmpty,
    desc: ClientConfigurationErrorMessages[tokenRequestEmpty]
  },
  logoutRequestEmptyError: {
    code: logoutRequestEmpty,
    desc: ClientConfigurationErrorMessages[logoutRequestEmpty]
  },
  invalidCodeChallengeMethod: {
    code: invalidCodeChallengeMethod,
    desc: ClientConfigurationErrorMessages[invalidCodeChallengeMethod]
  },
  invalidCodeChallengeParams: {
    code: pkceParamsMissing,
    desc: ClientConfigurationErrorMessages[pkceParamsMissing]
  },
  invalidCloudDiscoveryMetadata: {
    code: invalidCloudDiscoveryMetadata,
    desc: ClientConfigurationErrorMessages[invalidCloudDiscoveryMetadata]
  },
  invalidAuthorityMetadata: {
    code: invalidAuthorityMetadata,
    desc: ClientConfigurationErrorMessages[invalidAuthorityMetadata]
  },
  untrustedAuthority: {
    code: untrustedAuthority,
    desc: ClientConfigurationErrorMessages[untrustedAuthority]
  },
  missingSshJwk: {
    code: missingSshJwk,
    desc: ClientConfigurationErrorMessages[missingSshJwk]
  },
  missingSshKid: {
    code: missingSshKid,
    desc: ClientConfigurationErrorMessages[missingSshKid]
  },
  missingNonceAuthenticationHeader: {
    code: missingNonceAuthenticationHeader,
    desc: ClientConfigurationErrorMessages[missingNonceAuthenticationHeader]
  },
  invalidAuthenticationHeader: {
    code: invalidAuthenticationHeader,
    desc: ClientConfigurationErrorMessages[invalidAuthenticationHeader]
  },
  cannotSetOIDCOptions: {
    code: cannotSetOIDCOptions,
    desc: ClientConfigurationErrorMessages[cannotSetOIDCOptions]
  },
  cannotAllowPlatformBroker: {
    code: cannotAllowPlatformBroker,
    desc: ClientConfigurationErrorMessages[cannotAllowPlatformBroker]
  },
  authorityMismatch: {
    code: authorityMismatch,
    desc: ClientConfigurationErrorMessages[authorityMismatch]
  }
};
var ClientConfigurationError = class _ClientConfigurationError extends AuthError {
  constructor(errorCode) {
    super(errorCode, ClientConfigurationErrorMessages[errorCode]);
    this.name = "ClientConfigurationError";
    Object.setPrototypeOf(this, _ClientConfigurationError.prototype);
  }
};
function createClientConfigurationError(errorCode) {
  return new ClientConfigurationError(errorCode);
}

// node_modules/@azure/msal-common/dist/utils/StringUtils.mjs
var StringUtils = class {
  /**
   * Check if stringified object is empty
   * @param strObj
   */
  static isEmptyObj(strObj) {
    if (strObj) {
      try {
        const obj = JSON.parse(strObj);
        return Object.keys(obj).length === 0;
      } catch (e) {
      }
    }
    return true;
  }
  static startsWith(str, search) {
    return str.indexOf(search) === 0;
  }
  static endsWith(str, search) {
    return str.length >= search.length && str.lastIndexOf(search) === str.length - search.length;
  }
  /**
   * Parses string into an object.
   *
   * @param query
   */
  static queryStringToObject(query) {
    const obj = {};
    const params = query.split("&");
    const decode = (s) => decodeURIComponent(s.replace(/\+/g, " "));
    params.forEach((pair) => {
      if (pair.trim()) {
        const [key, value] = pair.split(/=(.+)/g, 2);
        if (key && value) {
          obj[decode(key)] = decode(value);
        }
      }
    });
    return obj;
  }
  /**
   * Trims entries in an array.
   *
   * @param arr
   */
  static trimArrayEntries(arr) {
    return arr.map((entry) => entry.trim());
  }
  /**
   * Removes empty strings from array
   * @param arr
   */
  static removeEmptyStringsFromArray(arr) {
    return arr.filter((entry) => {
      return !!entry;
    });
  }
  /**
   * Attempts to parse a string into JSON
   * @param str
   */
  static jsonParseHelper(str) {
    try {
      return JSON.parse(str);
    } catch (e) {
      return null;
    }
  }
  /**
   * Tests if a given string matches a given pattern, with support for wildcards and queries.
   * @param pattern Wildcard pattern to string match. Supports "*" for wildcards and "?" for queries
   * @param input String to match against
   */
  static matchPattern(pattern, input) {
    const regex = new RegExp(pattern.replace(/\\/g, "\\\\").replace(/\*/g, "[^ ]*").replace(/\?/g, "\\?"));
    return regex.test(input);
  }
};

// node_modules/@azure/msal-common/dist/authority/AuthorityType.mjs
var AuthorityType = {
  Default: 0,
  Adfs: 1,
  Dsts: 2,
  Ciam: 3
};

// node_modules/@azure/msal-common/dist/authority/ProtocolMode.mjs
var ProtocolMode = {
  AAD: "AAD",
  OIDC: "OIDC"
};

// node_modules/@azure/msal-common/dist/utils/UrlUtils.mjs
function stripLeadingHashOrQuery(responseString) {
  if (responseString.startsWith("#/")) {
    return responseString.substring(2);
  } else if (responseString.startsWith("#") || responseString.startsWith("?")) {
    return responseString.substring(1);
  }
  return responseString;
}
function getDeserializedResponse(responseString) {
  if (!responseString || responseString.indexOf("=") < 0) {
    return null;
  }
  try {
    const normalizedResponse = stripLeadingHashOrQuery(responseString);
    const deserializedHash = Object.fromEntries(new URLSearchParams(normalizedResponse));
    if (deserializedHash.code || deserializedHash.error || deserializedHash.error_description || deserializedHash.state) {
      return deserializedHash;
    }
  } catch (e) {
    throw createClientAuthError(hashNotDeserialized);
  }
  return null;
}

// node_modules/@azure/msal-common/dist/url/UrlString.mjs
var UrlString = class _UrlString {
  get urlString() {
    return this._urlString;
  }
  constructor(url) {
    this._urlString = url;
    if (!this._urlString) {
      throw createClientConfigurationError(urlEmptyError);
    }
    if (!url.includes("#")) {
      this._urlString = _UrlString.canonicalizeUri(url);
    }
  }
  /**
   * Ensure urls are lower case and end with a / character.
   * @param url
   */
  static canonicalizeUri(url) {
    if (url) {
      let lowerCaseUrl = url.toLowerCase();
      if (StringUtils.endsWith(lowerCaseUrl, "?")) {
        lowerCaseUrl = lowerCaseUrl.slice(0, -1);
      } else if (StringUtils.endsWith(lowerCaseUrl, "?/")) {
        lowerCaseUrl = lowerCaseUrl.slice(0, -2);
      }
      if (!StringUtils.endsWith(lowerCaseUrl, "/")) {
        lowerCaseUrl += "/";
      }
      return lowerCaseUrl;
    }
    return url;
  }
  /**
   * Throws if urlString passed is not a valid authority URI string.
   */
  validateAsUri() {
    let components;
    try {
      components = this.getUrlComponents();
    } catch (e) {
      throw createClientConfigurationError(urlParseError);
    }
    if (!components.HostNameAndPort || !components.PathSegments) {
      throw createClientConfigurationError(urlParseError);
    }
    if (!components.Protocol || components.Protocol.toLowerCase() !== "https:") {
      throw createClientConfigurationError(authorityUriInsecure);
    }
  }
  /**
   * Given a url and a query string return the url with provided query string appended
   * @param url
   * @param queryString
   */
  static appendQueryString(url, queryString) {
    if (!queryString) {
      return url;
    }
    return url.indexOf("?") < 0 ? `${url}?${queryString}` : `${url}&${queryString}`;
  }
  /**
   * Returns a url with the hash removed
   * @param url
   */
  static removeHashFromUrl(url) {
    return _UrlString.canonicalizeUri(url.split("#")[0]);
  }
  /**
   * Given a url like https://a:b/common/d?e=f#g, and a tenantId, returns https://a:b/tenantId/d
   * @param href The url
   * @param tenantId The tenant id to replace
   */
  replaceTenantPath(tenantId) {
    const urlObject = this.getUrlComponents();
    const pathArray = urlObject.PathSegments;
    if (tenantId && pathArray.length !== 0 && (pathArray[0] === AADAuthorityConstants.COMMON || pathArray[0] === AADAuthorityConstants.ORGANIZATIONS)) {
      pathArray[0] = tenantId;
    }
    return _UrlString.constructAuthorityUriFromObject(urlObject);
  }
  /**
   * Parses out the components from a url string.
   * @returns An object with the various components. Please cache this value insted of calling this multiple times on the same url.
   */
  getUrlComponents() {
    const regEx = RegExp("^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?");
    const match = this.urlString.match(regEx);
    if (!match) {
      throw createClientConfigurationError(urlParseError);
    }
    const urlComponents = {
      Protocol: match[1],
      HostNameAndPort: match[4],
      AbsolutePath: match[5],
      QueryString: match[7]
    };
    let pathSegments = urlComponents.AbsolutePath.split("/");
    pathSegments = pathSegments.filter((val) => val && val.length > 0);
    urlComponents.PathSegments = pathSegments;
    if (urlComponents.QueryString && urlComponents.QueryString.endsWith("/")) {
      urlComponents.QueryString = urlComponents.QueryString.substring(0, urlComponents.QueryString.length - 1);
    }
    return urlComponents;
  }
  static getDomainFromUrl(url) {
    const regEx = RegExp("^([^:/?#]+://)?([^/?#]*)");
    const match = url.match(regEx);
    if (!match) {
      throw createClientConfigurationError(urlParseError);
    }
    return match[2];
  }
  static getAbsoluteUrl(relativeUrl, baseUrl) {
    if (relativeUrl[0] === Constants.FORWARD_SLASH) {
      const url = new _UrlString(baseUrl);
      const baseComponents = url.getUrlComponents();
      return baseComponents.Protocol + "//" + baseComponents.HostNameAndPort + relativeUrl;
    }
    return relativeUrl;
  }
  static constructAuthorityUriFromObject(urlObject) {
    return new _UrlString(urlObject.Protocol + "//" + urlObject.HostNameAndPort + "/" + urlObject.PathSegments.join("/"));
  }
  /**
   * Check if the hash of the URL string contains known properties
   * @deprecated This API will be removed in a future version
   */
  static hashContainsKnownProperties(response) {
    return !!getDeserializedResponse(response);
  }
};

// node_modules/@azure/msal-common/dist/authority/AuthorityMetadata.mjs
var rawMetdataJSON = {
  endpointMetadata: {
    "login.microsoftonline.com": {
      token_endpoint: "https://login.microsoftonline.com/{tenantid}/oauth2/v2.0/token",
      jwks_uri: "https://login.microsoftonline.com/{tenantid}/discovery/v2.0/keys",
      issuer: "https://login.microsoftonline.com/{tenantid}/v2.0",
      authorization_endpoint: "https://login.microsoftonline.com/{tenantid}/oauth2/v2.0/authorize",
      end_session_endpoint: "https://login.microsoftonline.com/{tenantid}/oauth2/v2.0/logout"
    },
    "login.chinacloudapi.cn": {
      token_endpoint: "https://login.chinacloudapi.cn/{tenantid}/oauth2/v2.0/token",
      jwks_uri: "https://login.chinacloudapi.cn/{tenantid}/discovery/v2.0/keys",
      issuer: "https://login.partner.microsoftonline.cn/{tenantid}/v2.0",
      authorization_endpoint: "https://login.chinacloudapi.cn/{tenantid}/oauth2/v2.0/authorize",
      end_session_endpoint: "https://login.chinacloudapi.cn/{tenantid}/oauth2/v2.0/logout"
    },
    "login.microsoftonline.us": {
      token_endpoint: "https://login.microsoftonline.us/{tenantid}/oauth2/v2.0/token",
      jwks_uri: "https://login.microsoftonline.us/{tenantid}/discovery/v2.0/keys",
      issuer: "https://login.microsoftonline.us/{tenantid}/v2.0",
      authorization_endpoint: "https://login.microsoftonline.us/{tenantid}/oauth2/v2.0/authorize",
      end_session_endpoint: "https://login.microsoftonline.us/{tenantid}/oauth2/v2.0/logout"
    }
  },
  instanceDiscoveryMetadata: {
    tenant_discovery_endpoint: "https://{canonicalAuthority}/v2.0/.well-known/openid-configuration",
    metadata: [{
      preferred_network: "login.microsoftonline.com",
      preferred_cache: "login.windows.net",
      aliases: ["login.microsoftonline.com", "login.windows.net", "login.microsoft.com", "sts.windows.net"]
    }, {
      preferred_network: "login.partner.microsoftonline.cn",
      preferred_cache: "login.partner.microsoftonline.cn",
      aliases: ["login.partner.microsoftonline.cn", "login.chinacloudapi.cn"]
    }, {
      preferred_network: "login.microsoftonline.de",
      preferred_cache: "login.microsoftonline.de",
      aliases: ["login.microsoftonline.de"]
    }, {
      preferred_network: "login.microsoftonline.us",
      preferred_cache: "login.microsoftonline.us",
      aliases: ["login.microsoftonline.us", "login.usgovcloudapi.net"]
    }, {
      preferred_network: "login-us.microsoftonline.com",
      preferred_cache: "login-us.microsoftonline.com",
      aliases: ["login-us.microsoftonline.com"]
    }]
  }
};
var EndpointMetadata = rawMetdataJSON.endpointMetadata;
var InstanceDiscoveryMetadata = rawMetdataJSON.instanceDiscoveryMetadata;
var InstanceDiscoveryMetadataAliases = /* @__PURE__ */ new Set();
InstanceDiscoveryMetadata.metadata.forEach((metadataEntry) => {
  metadataEntry.aliases.forEach((alias) => {
    InstanceDiscoveryMetadataAliases.add(alias);
  });
});
function getCloudDiscoveryMetadataFromHardcodedValues(authorityHost) {
  const metadata = getCloudDiscoveryMetadataFromNetworkResponse(InstanceDiscoveryMetadata.metadata, authorityHost);
  return metadata;
}
function getCloudDiscoveryMetadataFromNetworkResponse(response, authorityHost) {
  for (let i = 0; i < response.length; i++) {
    const metadata = response[i];
    if (metadata.aliases.includes(authorityHost)) {
      return metadata;
    }
  }
  return null;
}

// node_modules/@azure/msal-common/dist/error/CacheErrorCodes.mjs
var cacheQuotaExceededErrorCode = "cache_quota_exceeded";
var cacheUnknownErrorCode = "cache_error_unknown";

// node_modules/@azure/msal-common/dist/error/CacheError.mjs
var CacheErrorMessages = {
  [cacheQuotaExceededErrorCode]: "Exceeded cache storage capacity.",
  [cacheUnknownErrorCode]: "Unexpected error occurred when using cache storage."
};

// node_modules/@azure/msal-common/dist/config/ClientConfiguration.mjs
var DEFAULT_SYSTEM_OPTIONS = {
  tokenRenewalOffsetSeconds: DEFAULT_TOKEN_RENEWAL_OFFSET_SEC,
  preventCorsPreflight: false
};
var DEFAULT_LOGGER_IMPLEMENTATION = {
  loggerCallback: () => {
  },
  piiLoggingEnabled: false,
  logLevel: LogLevel.Info,
  correlationId: Constants.EMPTY_STRING
};
var DEFAULT_LIBRARY_INFO = {
  sku: Constants.SKU,
  version,
  cpu: Constants.EMPTY_STRING,
  os: Constants.EMPTY_STRING
};
var DEFAULT_CLIENT_CREDENTIALS = {
  clientSecret: Constants.EMPTY_STRING,
  clientAssertion: void 0
};
var DEFAULT_AZURE_CLOUD_OPTIONS = {
  azureCloudInstance: AzureCloudInstance.None,
  tenant: `${Constants.DEFAULT_COMMON_TENANT}`
};

// node_modules/@azure/msal-common/dist/authority/OpenIdConfigResponse.mjs
function isOpenIdConfigResponse(response) {
  return response.hasOwnProperty("authorization_endpoint") && response.hasOwnProperty("token_endpoint") && response.hasOwnProperty("issuer") && response.hasOwnProperty("jwks_uri");
}

// node_modules/@azure/msal-common/dist/authority/CloudInstanceDiscoveryResponse.mjs
function isCloudInstanceDiscoveryResponse(response) {
  return response.hasOwnProperty("tenant_discovery_endpoint") && response.hasOwnProperty("metadata");
}

// node_modules/@azure/msal-common/dist/authority/CloudInstanceDiscoveryErrorResponse.mjs
function isCloudInstanceDiscoveryErrorResponse(response) {
  return response.hasOwnProperty("error") && response.hasOwnProperty("error_description");
}

// node_modules/@azure/msal-common/dist/telemetry/performance/PerformanceEvent.mjs
var PerformanceEvents = {
  /**
   * acquireTokenByCode API (msal-browser and msal-node).
   * Used to acquire tokens by trading an authorization code against the token endpoint.
   */
  AcquireTokenByCode: "acquireTokenByCode",
  /**
   * acquireTokenByRefreshToken API (msal-browser and msal-node).
   * Used to renew an access token using a refresh token against the token endpoint.
   */
  AcquireTokenByRefreshToken: "acquireTokenByRefreshToken",
  /**
   * acquireTokenSilent API (msal-browser and msal-node).
   * Used to silently acquire a new access token (from the cache or the network).
   */
  AcquireTokenSilent: "acquireTokenSilent",
  /**
   * acquireTokenSilentAsync (msal-browser).
   * Internal API for acquireTokenSilent.
   */
  AcquireTokenSilentAsync: "acquireTokenSilentAsync",
  /**
   * acquireTokenPopup (msal-browser).
   * Used to acquire a new access token interactively through pop ups
   */
  AcquireTokenPopup: "acquireTokenPopup",
  /**
   * acquireTokenPreRedirect (msal-browser).
   * First part of the redirect flow.
   * Used to acquire a new access token interactively through redirects.
   */
  AcquireTokenPreRedirect: "acquireTokenPreRedirect",
  /**
   * acquireTokenRedirect (msal-browser).
   * Second part of the redirect flow.
   * Used to acquire a new access token interactively through redirects.
   */
  AcquireTokenRedirect: "acquireTokenRedirect",
  /**
   * getPublicKeyThumbprint API in CryptoOpts class (msal-browser).
   * Used to generate a public/private keypair and generate a public key thumbprint for pop requests.
   */
  CryptoOptsGetPublicKeyThumbprint: "cryptoOptsGetPublicKeyThumbprint",
  /**
   * signJwt API in CryptoOpts class (msal-browser).
   * Used to signed a pop token.
   */
  CryptoOptsSignJwt: "cryptoOptsSignJwt",
  /**
   * acquireToken API in the SilentCacheClient class (msal-browser).
   * Used to read access tokens from the cache.
   */
  SilentCacheClientAcquireToken: "silentCacheClientAcquireToken",
  /**
   * acquireToken API in the SilentIframeClient class (msal-browser).
   * Used to acquire a new set of tokens from the authorize endpoint in a hidden iframe.
   */
  SilentIframeClientAcquireToken: "silentIframeClientAcquireToken",
  AwaitConcurrentIframe: "awaitConcurrentIframe",
  /**
   * acquireToken API in SilentRereshClient (msal-browser).
   * Used to acquire a new set of tokens from the token endpoint using a refresh token.
   */
  SilentRefreshClientAcquireToken: "silentRefreshClientAcquireToken",
  /**
   * ssoSilent API (msal-browser).
   * Used to silently acquire an authorization code and set of tokens using a hidden iframe.
   */
  SsoSilent: "ssoSilent",
  /**
   * getDiscoveredAuthority API in StandardInteractionClient class (msal-browser).
   * Used to load authority metadata for a request.
   */
  StandardInteractionClientGetDiscoveredAuthority: "standardInteractionClientGetDiscoveredAuthority",
  /**
   * acquireToken APIs in msal-browser.
   * Used to make an /authorize endpoint call with native brokering enabled.
   */
  FetchAccountIdWithNativeBroker: "fetchAccountIdWithNativeBroker",
  /**
   * acquireToken API in NativeInteractionClient class (msal-browser).
   * Used to acquire a token from Native component when native brokering is enabled.
   */
  NativeInteractionClientAcquireToken: "nativeInteractionClientAcquireToken",
  /**
   * Time spent creating default headers for requests to token endpoint
   */
  BaseClientCreateTokenRequestHeaders: "baseClientCreateTokenRequestHeaders",
  /**
   * Time spent sending/waiting for the response of a request to the token endpoint
   */
  NetworkClientSendPostRequestAsync: "networkClientSendPostRequestAsync",
  RefreshTokenClientExecutePostToTokenEndpoint: "refreshTokenClientExecutePostToTokenEndpoint",
  AuthorizationCodeClientExecutePostToTokenEndpoint: "authorizationCodeClientExecutePostToTokenEndpoint",
  /**
   * Used to measure the time taken for completing embedded-broker handshake (PW-Broker).
   */
  BrokerHandhshake: "brokerHandshake",
  /**
   * acquireTokenByRefreshToken API in BrokerClientApplication (PW-Broker) .
   */
  AcquireTokenByRefreshTokenInBroker: "acquireTokenByRefreshTokenInBroker",
  /**
   * Time taken for token acquisition by broker
   */
  AcquireTokenByBroker: "acquireTokenByBroker",
  /**
   * Time spent on the network for refresh token acquisition
   */
  RefreshTokenClientExecuteTokenRequest: "refreshTokenClientExecuteTokenRequest",
  /**
   * Time taken for acquiring refresh token , records RT size
   */
  RefreshTokenClientAcquireToken: "refreshTokenClientAcquireToken",
  /**
   * Time taken for acquiring cached refresh token
   */
  RefreshTokenClientAcquireTokenWithCachedRefreshToken: "refreshTokenClientAcquireTokenWithCachedRefreshToken",
  /**
   * acquireTokenByRefreshToken API in RefreshTokenClient (msal-common).
   */
  RefreshTokenClientAcquireTokenByRefreshToken: "refreshTokenClientAcquireTokenByRefreshToken",
  /**
   * Helper function to create token request body in RefreshTokenClient (msal-common).
   */
  RefreshTokenClientCreateTokenRequestBody: "refreshTokenClientCreateTokenRequestBody",
  /**
   * acquireTokenFromCache (msal-browser).
   * Internal API for acquiring token from cache
   */
  AcquireTokenFromCache: "acquireTokenFromCache",
  SilentFlowClientAcquireCachedToken: "silentFlowClientAcquireCachedToken",
  SilentFlowClientGenerateResultFromCacheRecord: "silentFlowClientGenerateResultFromCacheRecord",
  /**
   * acquireTokenBySilentIframe (msal-browser).
   * Internal API for acquiring token by silent Iframe
   */
  AcquireTokenBySilentIframe: "acquireTokenBySilentIframe",
  /**
   * Internal API for initializing base request in BaseInteractionClient (msal-browser)
   */
  InitializeBaseRequest: "initializeBaseRequest",
  /**
   * Internal API for initializing silent request in SilentCacheClient (msal-browser)
   */
  InitializeSilentRequest: "initializeSilentRequest",
  InitializeClientApplication: "initializeClientApplication",
  InitializeCache: "initializeCache",
  /**
   * Helper function in SilentIframeClient class (msal-browser).
   */
  SilentIframeClientTokenHelper: "silentIframeClientTokenHelper",
  /**
   * SilentHandler
   */
  SilentHandlerInitiateAuthRequest: "silentHandlerInitiateAuthRequest",
  SilentHandlerMonitorIframeForHash: "silentHandlerMonitorIframeForHash",
  SilentHandlerLoadFrame: "silentHandlerLoadFrame",
  SilentHandlerLoadFrameSync: "silentHandlerLoadFrameSync",
  /**
   * Helper functions in StandardInteractionClient class (msal-browser)
   */
  StandardInteractionClientCreateAuthCodeClient: "standardInteractionClientCreateAuthCodeClient",
  StandardInteractionClientGetClientConfiguration: "standardInteractionClientGetClientConfiguration",
  StandardInteractionClientInitializeAuthorizationRequest: "standardInteractionClientInitializeAuthorizationRequest",
  StandardInteractionClientInitializeAuthorizationCodeRequest: "standardInteractionClientInitializeAuthorizationCodeRequest",
  /**
   * getAuthCodeUrl API (msal-browser and msal-node).
   */
  GetAuthCodeUrl: "getAuthCodeUrl",
  /**
   * Functions from InteractionHandler (msal-browser)
   */
  HandleCodeResponseFromServer: "handleCodeResponseFromServer",
  HandleCodeResponse: "handleCodeResponse",
  UpdateTokenEndpointAuthority: "updateTokenEndpointAuthority",
  /**
   * APIs in Authorization Code Client (msal-common)
   */
  AuthClientAcquireToken: "authClientAcquireToken",
  AuthClientExecuteTokenRequest: "authClientExecuteTokenRequest",
  AuthClientCreateTokenRequestBody: "authClientCreateTokenRequestBody",
  AuthClientCreateQueryString: "authClientCreateQueryString",
  /**
   * Generate functions in PopTokenGenerator (msal-common)
   */
  PopTokenGenerateCnf: "popTokenGenerateCnf",
  PopTokenGenerateKid: "popTokenGenerateKid",
  /**
   * handleServerTokenResponse API in ResponseHandler (msal-common)
   */
  HandleServerTokenResponse: "handleServerTokenResponse",
  DeserializeResponse: "deserializeResponse",
  /**
   * Authority functions
   */
  AuthorityFactoryCreateDiscoveredInstance: "authorityFactoryCreateDiscoveredInstance",
  AuthorityResolveEndpointsAsync: "authorityResolveEndpointsAsync",
  AuthorityResolveEndpointsFromLocalSources: "authorityResolveEndpointsFromLocalSources",
  AuthorityGetCloudDiscoveryMetadataFromNetwork: "authorityGetCloudDiscoveryMetadataFromNetwork",
  AuthorityUpdateCloudDiscoveryMetadata: "authorityUpdateCloudDiscoveryMetadata",
  AuthorityGetEndpointMetadataFromNetwork: "authorityGetEndpointMetadataFromNetwork",
  AuthorityUpdateEndpointMetadata: "authorityUpdateEndpointMetadata",
  AuthorityUpdateMetadataWithRegionalInformation: "authorityUpdateMetadataWithRegionalInformation",
  /**
   * Region Discovery functions
   */
  RegionDiscoveryDetectRegion: "regionDiscoveryDetectRegion",
  RegionDiscoveryGetRegionFromIMDS: "regionDiscoveryGetRegionFromIMDS",
  RegionDiscoveryGetCurrentVersion: "regionDiscoveryGetCurrentVersion",
  AcquireTokenByCodeAsync: "acquireTokenByCodeAsync",
  GetEndpointMetadataFromNetwork: "getEndpointMetadataFromNetwork",
  GetCloudDiscoveryMetadataFromNetworkMeasurement: "getCloudDiscoveryMetadataFromNetworkMeasurement",
  HandleRedirectPromiseMeasurement: "handleRedirectPromise",
  HandleNativeRedirectPromiseMeasurement: "handleNativeRedirectPromise",
  UpdateCloudDiscoveryMetadataMeasurement: "updateCloudDiscoveryMetadataMeasurement",
  UsernamePasswordClientAcquireToken: "usernamePasswordClientAcquireToken",
  NativeMessageHandlerHandshake: "nativeMessageHandlerHandshake",
  NativeGenerateAuthResult: "nativeGenerateAuthResult",
  RemoveHiddenIframe: "removeHiddenIframe",
  /**
   * Cache operations
   */
  ClearTokensAndKeysWithClaims: "clearTokensAndKeysWithClaims",
  CacheManagerGetRefreshToken: "cacheManagerGetRefreshToken",
  ImportExistingCache: "importExistingCache",
  SetUserData: "setUserData",
  LocalStorageUpdated: "localStorageUpdated",
  /**
   * Crypto Operations
   */
  GeneratePkceCodes: "generatePkceCodes",
  GenerateCodeVerifier: "generateCodeVerifier",
  GenerateCodeChallengeFromVerifier: "generateCodeChallengeFromVerifier",
  Sha256Digest: "sha256Digest",
  GetRandomValues: "getRandomValues",
  GenerateHKDF: "generateHKDF",
  GenerateBaseKey: "generateBaseKey",
  Base64Decode: "base64Decode",
  UrlEncodeArr: "urlEncodeArr",
  Encrypt: "encrypt",
  Decrypt: "decrypt"
};
var PerformanceEventAbbreviations = /* @__PURE__ */ new Map([[PerformanceEvents.AcquireTokenByCode, "ATByCode"], [PerformanceEvents.AcquireTokenByRefreshToken, "ATByRT"], [PerformanceEvents.AcquireTokenSilent, "ATS"], [PerformanceEvents.AcquireTokenSilentAsync, "ATSAsync"], [PerformanceEvents.AcquireTokenPopup, "ATPopup"], [PerformanceEvents.AcquireTokenRedirect, "ATRedirect"], [PerformanceEvents.CryptoOptsGetPublicKeyThumbprint, "CryptoGetPKThumb"], [PerformanceEvents.CryptoOptsSignJwt, "CryptoSignJwt"], [PerformanceEvents.SilentCacheClientAcquireToken, "SltCacheClientAT"], [PerformanceEvents.SilentIframeClientAcquireToken, "SltIframeClientAT"], [PerformanceEvents.SilentRefreshClientAcquireToken, "SltRClientAT"], [PerformanceEvents.SsoSilent, "SsoSlt"], [PerformanceEvents.StandardInteractionClientGetDiscoveredAuthority, "StdIntClientGetDiscAuth"], [PerformanceEvents.FetchAccountIdWithNativeBroker, "FetchAccIdWithNtvBroker"], [PerformanceEvents.NativeInteractionClientAcquireToken, "NtvIntClientAT"], [PerformanceEvents.BaseClientCreateTokenRequestHeaders, "BaseClientCreateTReqHead"], [PerformanceEvents.NetworkClientSendPostRequestAsync, "NetClientSendPost"], [PerformanceEvents.RefreshTokenClientExecutePostToTokenEndpoint, "RTClientExecPost"], [PerformanceEvents.AuthorizationCodeClientExecutePostToTokenEndpoint, "AuthCodeClientExecPost"], [PerformanceEvents.BrokerHandhshake, "BrokerHandshake"], [PerformanceEvents.AcquireTokenByRefreshTokenInBroker, "ATByRTInBroker"], [PerformanceEvents.AcquireTokenByBroker, "ATByBroker"], [PerformanceEvents.RefreshTokenClientExecuteTokenRequest, "RTClientExecTReq"], [PerformanceEvents.RefreshTokenClientAcquireToken, "RTClientAT"], [PerformanceEvents.RefreshTokenClientAcquireTokenWithCachedRefreshToken, "RTClientATWithCachedRT"], [PerformanceEvents.RefreshTokenClientAcquireTokenByRefreshToken, "RTClientATByRT"], [PerformanceEvents.RefreshTokenClientCreateTokenRequestBody, "RTClientCreateTReqBody"], [PerformanceEvents.AcquireTokenFromCache, "ATFromCache"], [PerformanceEvents.SilentFlowClientAcquireCachedToken, "SltFlowClientATCached"], [PerformanceEvents.SilentFlowClientGenerateResultFromCacheRecord, "SltFlowClientGenResFromCache"], [PerformanceEvents.AcquireTokenBySilentIframe, "ATBySltIframe"], [PerformanceEvents.InitializeBaseRequest, "InitBaseReq"], [PerformanceEvents.InitializeSilentRequest, "InitSltReq"], [PerformanceEvents.InitializeClientApplication, "InitClientApplication"], [PerformanceEvents.InitializeCache, "InitCache"], [PerformanceEvents.ImportExistingCache, "importCache"], [PerformanceEvents.SetUserData, "setUserData"], [PerformanceEvents.LocalStorageUpdated, "localStorageUpdated"], [PerformanceEvents.SilentIframeClientTokenHelper, "SIClientTHelper"], [PerformanceEvents.SilentHandlerInitiateAuthRequest, "SHandlerInitAuthReq"], [PerformanceEvents.SilentHandlerMonitorIframeForHash, "SltHandlerMonitorIframeForHash"], [PerformanceEvents.SilentHandlerLoadFrame, "SHandlerLoadFrame"], [PerformanceEvents.SilentHandlerLoadFrameSync, "SHandlerLoadFrameSync"], [PerformanceEvents.StandardInteractionClientCreateAuthCodeClient, "StdIntClientCreateAuthCodeClient"], [PerformanceEvents.StandardInteractionClientGetClientConfiguration, "StdIntClientGetClientConf"], [PerformanceEvents.StandardInteractionClientInitializeAuthorizationRequest, "StdIntClientInitAuthReq"], [PerformanceEvents.StandardInteractionClientInitializeAuthorizationCodeRequest, "StdIntClientInitAuthCodeReq"], [PerformanceEvents.GetAuthCodeUrl, "GetAuthCodeUrl"], [PerformanceEvents.HandleCodeResponseFromServer, "HandleCodeResFromServer"], [PerformanceEvents.HandleCodeResponse, "HandleCodeResp"], [PerformanceEvents.UpdateTokenEndpointAuthority, "UpdTEndpointAuth"], [PerformanceEvents.AuthClientAcquireToken, "AuthClientAT"], [PerformanceEvents.AuthClientExecuteTokenRequest, "AuthClientExecTReq"], [PerformanceEvents.AuthClientCreateTokenRequestBody, "AuthClientCreateTReqBody"], [PerformanceEvents.AuthClientCreateQueryString, "AuthClientCreateQueryStr"], [PerformanceEvents.PopTokenGenerateCnf, "PopTGenCnf"], [PerformanceEvents.PopTokenGenerateKid, "PopTGenKid"], [PerformanceEvents.HandleServerTokenResponse, "HandleServerTRes"], [PerformanceEvents.DeserializeResponse, "DeserializeRes"], [PerformanceEvents.AuthorityFactoryCreateDiscoveredInstance, "AuthFactCreateDiscInst"], [PerformanceEvents.AuthorityResolveEndpointsAsync, "AuthResolveEndpointsAsync"], [PerformanceEvents.AuthorityResolveEndpointsFromLocalSources, "AuthResolveEndpointsFromLocal"], [PerformanceEvents.AuthorityGetCloudDiscoveryMetadataFromNetwork, "AuthGetCDMetaFromNet"], [PerformanceEvents.AuthorityUpdateCloudDiscoveryMetadata, "AuthUpdCDMeta"], [PerformanceEvents.AuthorityGetEndpointMetadataFromNetwork, "AuthUpdCDMetaFromNet"], [PerformanceEvents.AuthorityUpdateEndpointMetadata, "AuthUpdEndpointMeta"], [PerformanceEvents.AuthorityUpdateMetadataWithRegionalInformation, "AuthUpdMetaWithRegInfo"], [PerformanceEvents.RegionDiscoveryDetectRegion, "RegDiscDetectReg"], [PerformanceEvents.RegionDiscoveryGetRegionFromIMDS, "RegDiscGetRegFromIMDS"], [PerformanceEvents.RegionDiscoveryGetCurrentVersion, "RegDiscGetCurrentVer"], [PerformanceEvents.AcquireTokenByCodeAsync, "ATByCodeAsync"], [PerformanceEvents.GetEndpointMetadataFromNetwork, "GetEndpointMetaFromNet"], [PerformanceEvents.GetCloudDiscoveryMetadataFromNetworkMeasurement, "GetCDMetaFromNet"], [PerformanceEvents.HandleRedirectPromiseMeasurement, "HandleRedirectPromise"], [PerformanceEvents.HandleNativeRedirectPromiseMeasurement, "HandleNtvRedirectPromise"], [PerformanceEvents.UpdateCloudDiscoveryMetadataMeasurement, "UpdateCDMeta"], [PerformanceEvents.UsernamePasswordClientAcquireToken, "UserPassClientAT"], [PerformanceEvents.NativeMessageHandlerHandshake, "NtvMsgHandlerHandshake"], [PerformanceEvents.NativeGenerateAuthResult, "NtvGenAuthRes"], [PerformanceEvents.RemoveHiddenIframe, "RemoveHiddenIframe"], [PerformanceEvents.ClearTokensAndKeysWithClaims, "ClearTAndKeysWithClaims"], [PerformanceEvents.CacheManagerGetRefreshToken, "CacheManagerGetRT"], [PerformanceEvents.GeneratePkceCodes, "GenPkceCodes"], [PerformanceEvents.GenerateCodeVerifier, "GenCodeVerifier"], [PerformanceEvents.GenerateCodeChallengeFromVerifier, "GenCodeChallengeFromVerifier"], [PerformanceEvents.Sha256Digest, "Sha256Digest"], [PerformanceEvents.GetRandomValues, "GetRandomValues"], [PerformanceEvents.GenerateHKDF, "genHKDF"], [PerformanceEvents.GenerateBaseKey, "genBaseKey"], [PerformanceEvents.Base64Decode, "b64Decode"], [PerformanceEvents.UrlEncodeArr, "urlEncArr"], [PerformanceEvents.Encrypt, "encrypt"], [PerformanceEvents.Decrypt, "decrypt"]]);
var PerformanceEventStatus = {
  NotStarted: 0,
  InProgress: 1,
  Completed: 2
};

// node_modules/@azure/msal-common/dist/utils/FunctionWrappers.mjs
var invoke = (callback, eventName, logger, telemetryClient, correlationId) => {
  return (...args) => {
    logger.trace(`Executing function ${eventName}`);
    const inProgressEvent = telemetryClient?.startMeasurement(eventName, correlationId);
    if (correlationId) {
      const eventCount = eventName + "CallCount";
      telemetryClient?.incrementFields({
        [eventCount]: 1
      }, correlationId);
    }
    try {
      const result = callback(...args);
      inProgressEvent?.end({
        success: true
      });
      logger.trace(`Returning result from ${eventName}`);
      return result;
    } catch (e) {
      logger.trace(`Error occurred in ${eventName}`);
      try {
        logger.trace(JSON.stringify(e));
      } catch (e2) {
        logger.trace("Unable to print error message.");
      }
      inProgressEvent?.end({
        success: false
      }, e);
      throw e;
    }
  };
};
var invokeAsync = (callback, eventName, logger, telemetryClient, correlationId) => {
  return (...args) => {
    logger.trace(`Executing function ${eventName}`);
    const inProgressEvent = telemetryClient?.startMeasurement(eventName, correlationId);
    if (correlationId) {
      const eventCount = eventName + "CallCount";
      telemetryClient?.incrementFields({
        [eventCount]: 1
      }, correlationId);
    }
    telemetryClient?.setPreQueueTime(eventName, correlationId);
    return callback(...args).then((response) => {
      logger.trace(`Returning result from ${eventName}`);
      inProgressEvent?.end({
        success: true
      });
      return response;
    }).catch((e) => {
      logger.trace(`Error occurred in ${eventName}`);
      try {
        logger.trace(JSON.stringify(e));
      } catch (e2) {
        logger.trace("Unable to print error message.");
      }
      inProgressEvent?.end({
        success: false
      }, e);
      throw e;
    });
  };
};

// node_modules/@azure/msal-common/dist/authority/RegionDiscovery.mjs
var RegionDiscovery = class _RegionDiscovery {
  constructor(networkInterface, logger, performanceClient, correlationId) {
    this.networkInterface = networkInterface;
    this.logger = logger;
    this.performanceClient = performanceClient;
    this.correlationId = correlationId;
  }
  /**
   * Detect the region from the application's environment.
   *
   * @returns Promise<string | null>
   */
  detectRegion(environmentRegion, regionDiscoveryMetadata) {
    return __async(this, null, function* () {
      this.performanceClient?.addQueueMeasurement(PerformanceEvents.RegionDiscoveryDetectRegion, this.correlationId);
      let autodetectedRegionName = environmentRegion;
      if (!autodetectedRegionName) {
        const options = _RegionDiscovery.IMDS_OPTIONS;
        try {
          const localIMDSVersionResponse = yield invokeAsync(this.getRegionFromIMDS.bind(this), PerformanceEvents.RegionDiscoveryGetRegionFromIMDS, this.logger, this.performanceClient, this.correlationId)(Constants.IMDS_VERSION, options);
          if (localIMDSVersionResponse.status === ResponseCodes.httpSuccess) {
            autodetectedRegionName = localIMDSVersionResponse.body;
            regionDiscoveryMetadata.region_source = RegionDiscoverySources.IMDS;
          }
          if (localIMDSVersionResponse.status === ResponseCodes.httpBadRequest) {
            const currentIMDSVersion = yield invokeAsync(this.getCurrentVersion.bind(this), PerformanceEvents.RegionDiscoveryGetCurrentVersion, this.logger, this.performanceClient, this.correlationId)(options);
            if (!currentIMDSVersion) {
              regionDiscoveryMetadata.region_source = RegionDiscoverySources.FAILED_AUTO_DETECTION;
              return null;
            }
            const currentIMDSVersionResponse = yield invokeAsync(this.getRegionFromIMDS.bind(this), PerformanceEvents.RegionDiscoveryGetRegionFromIMDS, this.logger, this.performanceClient, this.correlationId)(currentIMDSVersion, options);
            if (currentIMDSVersionResponse.status === ResponseCodes.httpSuccess) {
              autodetectedRegionName = currentIMDSVersionResponse.body;
              regionDiscoveryMetadata.region_source = RegionDiscoverySources.IMDS;
            }
          }
        } catch (e) {
          regionDiscoveryMetadata.region_source = RegionDiscoverySources.FAILED_AUTO_DETECTION;
          return null;
        }
      } else {
        regionDiscoveryMetadata.region_source = RegionDiscoverySources.ENVIRONMENT_VARIABLE;
      }
      if (!autodetectedRegionName) {
        regionDiscoveryMetadata.region_source = RegionDiscoverySources.FAILED_AUTO_DETECTION;
      }
      return autodetectedRegionName || null;
    });
  }
  /**
   * Make the call to the IMDS endpoint
   *
   * @param imdsEndpointUrl
   * @returns Promise<NetworkResponse<string>>
   */
  getRegionFromIMDS(version4, options) {
    return __async(this, null, function* () {
      this.performanceClient?.addQueueMeasurement(PerformanceEvents.RegionDiscoveryGetRegionFromIMDS, this.correlationId);
      return this.networkInterface.sendGetRequestAsync(`${Constants.IMDS_ENDPOINT}?api-version=${version4}&format=text`, options, Constants.IMDS_TIMEOUT);
    });
  }
  /**
   * Get the most recent version of the IMDS endpoint available
   *
   * @returns Promise<string | null>
   */
  getCurrentVersion(options) {
    return __async(this, null, function* () {
      this.performanceClient?.addQueueMeasurement(PerformanceEvents.RegionDiscoveryGetCurrentVersion, this.correlationId);
      try {
        const response = yield this.networkInterface.sendGetRequestAsync(`${Constants.IMDS_ENDPOINT}?format=json`, options);
        if (response.status === ResponseCodes.httpBadRequest && response.body && response.body["newest-versions"] && response.body["newest-versions"].length > 0) {
          return response.body["newest-versions"][0];
        }
        return null;
      } catch (e) {
        return null;
      }
    });
  }
};
RegionDiscovery.IMDS_OPTIONS = {
  headers: {
    Metadata: "true"
  }
};

// node_modules/@azure/msal-common/dist/authority/Authority.mjs
var Authority = class _Authority {
  constructor(authority, networkInterface, cacheManager, authorityOptions, logger, correlationId, performanceClient, managedIdentity) {
    this.canonicalAuthority = authority;
    this._canonicalAuthority.validateAsUri();
    this.networkInterface = networkInterface;
    this.cacheManager = cacheManager;
    this.authorityOptions = authorityOptions;
    this.regionDiscoveryMetadata = {
      region_used: void 0,
      region_source: void 0,
      region_outcome: void 0
    };
    this.logger = logger;
    this.performanceClient = performanceClient;
    this.correlationId = correlationId;
    this.managedIdentity = managedIdentity || false;
    this.regionDiscovery = new RegionDiscovery(networkInterface, this.logger, this.performanceClient, this.correlationId);
  }
  /**
   * Get {@link AuthorityType}
   * @param authorityUri {@link IUri}
   * @private
   */
  getAuthorityType(authorityUri) {
    if (authorityUri.HostNameAndPort.endsWith(Constants.CIAM_AUTH_URL)) {
      return AuthorityType.Ciam;
    }
    const pathSegments = authorityUri.PathSegments;
    if (pathSegments.length) {
      switch (pathSegments[0].toLowerCase()) {
        case Constants.ADFS:
          return AuthorityType.Adfs;
        case Constants.DSTS:
          return AuthorityType.Dsts;
      }
    }
    return AuthorityType.Default;
  }
  // See above for AuthorityType
  get authorityType() {
    return this.getAuthorityType(this.canonicalAuthorityUrlComponents);
  }
  /**
   * ProtocolMode enum representing the way endpoints are constructed.
   */
  get protocolMode() {
    return this.authorityOptions.protocolMode;
  }
  /**
   * Returns authorityOptions which can be used to reinstantiate a new authority instance
   */
  get options() {
    return this.authorityOptions;
  }
  /**
   * A URL that is the authority set by the developer
   */
  get canonicalAuthority() {
    return this._canonicalAuthority.urlString;
  }
  /**
   * Sets canonical authority.
   */
  set canonicalAuthority(url) {
    this._canonicalAuthority = new UrlString(url);
    this._canonicalAuthority.validateAsUri();
    this._canonicalAuthorityUrlComponents = null;
  }
  /**
   * Get authority components.
   */
  get canonicalAuthorityUrlComponents() {
    if (!this._canonicalAuthorityUrlComponents) {
      this._canonicalAuthorityUrlComponents = this._canonicalAuthority.getUrlComponents();
    }
    return this._canonicalAuthorityUrlComponents;
  }
  /**
   * Get hostname and port i.e. login.microsoftonline.com
   */
  get hostnameAndPort() {
    return this.canonicalAuthorityUrlComponents.HostNameAndPort.toLowerCase();
  }
  /**
   * Get tenant for authority.
   */
  get tenant() {
    return this.canonicalAuthorityUrlComponents.PathSegments[0];
  }
  /**
   * OAuth /authorize endpoint for requests
   */
  get authorizationEndpoint() {
    if (this.discoveryComplete()) {
      return this.replacePath(this.metadata.authorization_endpoint);
    } else {
      throw createClientAuthError(endpointResolutionError);
    }
  }
  /**
   * OAuth /token endpoint for requests
   */
  get tokenEndpoint() {
    if (this.discoveryComplete()) {
      return this.replacePath(this.metadata.token_endpoint);
    } else {
      throw createClientAuthError(endpointResolutionError);
    }
  }
  get deviceCodeEndpoint() {
    if (this.discoveryComplete()) {
      return this.replacePath(this.metadata.token_endpoint.replace("/token", "/devicecode"));
    } else {
      throw createClientAuthError(endpointResolutionError);
    }
  }
  /**
   * OAuth logout endpoint for requests
   */
  get endSessionEndpoint() {
    if (this.discoveryComplete()) {
      if (!this.metadata.end_session_endpoint) {
        throw createClientAuthError(endSessionEndpointNotSupported);
      }
      return this.replacePath(this.metadata.end_session_endpoint);
    } else {
      throw createClientAuthError(endpointResolutionError);
    }
  }
  /**
   * OAuth issuer for requests
   */
  get selfSignedJwtAudience() {
    if (this.discoveryComplete()) {
      return this.replacePath(this.metadata.issuer);
    } else {
      throw createClientAuthError(endpointResolutionError);
    }
  }
  /**
   * Jwks_uri for token signing keys
   */
  get jwksUri() {
    if (this.discoveryComplete()) {
      return this.replacePath(this.metadata.jwks_uri);
    } else {
      throw createClientAuthError(endpointResolutionError);
    }
  }
  /**
   * Returns a flag indicating that tenant name can be replaced in authority {@link IUri}
   * @param authorityUri {@link IUri}
   * @private
   */
  canReplaceTenant(authorityUri) {
    return authorityUri.PathSegments.length === 1 && !_Authority.reservedTenantDomains.has(authorityUri.PathSegments[0]) && this.getAuthorityType(authorityUri) === AuthorityType.Default && this.protocolMode === ProtocolMode.AAD;
  }
  /**
   * Replaces tenant in url path with current tenant. Defaults to common.
   * @param urlString
   */
  replaceTenant(urlString) {
    return urlString.replace(/{tenant}|{tenantid}/g, this.tenant);
  }
  /**
   * Replaces path such as tenant or policy with the current tenant or policy.
   * @param urlString
   */
  replacePath(urlString) {
    let endpoint = urlString;
    const cachedAuthorityUrl = new UrlString(this.metadata.canonical_authority);
    const cachedAuthorityUrlComponents = cachedAuthorityUrl.getUrlComponents();
    const cachedAuthorityParts = cachedAuthorityUrlComponents.PathSegments;
    const currentAuthorityParts = this.canonicalAuthorityUrlComponents.PathSegments;
    currentAuthorityParts.forEach((currentPart, index) => {
      let cachedPart = cachedAuthorityParts[index];
      if (index === 0 && this.canReplaceTenant(cachedAuthorityUrlComponents)) {
        const tenantId = new UrlString(this.metadata.authorization_endpoint).getUrlComponents().PathSegments[0];
        if (cachedPart !== tenantId) {
          this.logger.verbose(`Replacing tenant domain name ${cachedPart} with id ${tenantId}`);
          cachedPart = tenantId;
        }
      }
      if (currentPart !== cachedPart) {
        endpoint = endpoint.replace(`/${cachedPart}/`, `/${currentPart}/`);
      }
    });
    return this.replaceTenant(endpoint);
  }
  /**
   * The default open id configuration endpoint for any canonical authority.
   */
  get defaultOpenIdConfigurationEndpoint() {
    const canonicalAuthorityHost = this.hostnameAndPort;
    if (this.canonicalAuthority.endsWith("v2.0/") || this.authorityType === AuthorityType.Adfs || this.protocolMode !== ProtocolMode.AAD && !this.isAliasOfKnownMicrosoftAuthority(canonicalAuthorityHost)) {
      return `${this.canonicalAuthority}.well-known/openid-configuration`;
    }
    return `${this.canonicalAuthority}v2.0/.well-known/openid-configuration`;
  }
  /**
   * Boolean that returns whether or not tenant discovery has been completed.
   */
  discoveryComplete() {
    return !!this.metadata;
  }
  /**
   * Perform endpoint discovery to discover aliases, preferred_cache, preferred_network
   * and the /authorize, /token and logout endpoints.
   */
  resolveEndpointsAsync() {
    return __async(this, null, function* () {
      this.performanceClient?.addQueueMeasurement(PerformanceEvents.AuthorityResolveEndpointsAsync, this.correlationId);
      const metadataEntity = this.getCurrentMetadataEntity();
      const cloudDiscoverySource = yield invokeAsync(this.updateCloudDiscoveryMetadata.bind(this), PerformanceEvents.AuthorityUpdateCloudDiscoveryMetadata, this.logger, this.performanceClient, this.correlationId)(metadataEntity);
      this.canonicalAuthority = this.canonicalAuthority.replace(this.hostnameAndPort, metadataEntity.preferred_network);
      const endpointSource = yield invokeAsync(this.updateEndpointMetadata.bind(this), PerformanceEvents.AuthorityUpdateEndpointMetadata, this.logger, this.performanceClient, this.correlationId)(metadataEntity);
      this.updateCachedMetadata(metadataEntity, cloudDiscoverySource, {
        source: endpointSource
      });
      this.performanceClient?.addFields({
        cloudDiscoverySource,
        authorityEndpointSource: endpointSource
      }, this.correlationId);
    });
  }
  /**
   * Returns metadata entity from cache if it exists, otherwiser returns a new metadata entity built
   * from the configured canonical authority
   * @returns
   */
  getCurrentMetadataEntity() {
    let metadataEntity = this.cacheManager.getAuthorityMetadataByAlias(this.hostnameAndPort);
    if (!metadataEntity) {
      metadataEntity = {
        aliases: [],
        preferred_cache: this.hostnameAndPort,
        preferred_network: this.hostnameAndPort,
        canonical_authority: this.canonicalAuthority,
        authorization_endpoint: "",
        token_endpoint: "",
        end_session_endpoint: "",
        issuer: "",
        aliasesFromNetwork: false,
        endpointsFromNetwork: false,
        expiresAt: generateAuthorityMetadataExpiresAt(),
        jwks_uri: ""
      };
    }
    return metadataEntity;
  }
  /**
   * Updates cached metadata based on metadata source and sets the instance's metadata
   * property to the same value
   * @param metadataEntity
   * @param cloudDiscoverySource
   * @param endpointMetadataResult
   */
  updateCachedMetadata(metadataEntity, cloudDiscoverySource, endpointMetadataResult) {
    if (cloudDiscoverySource !== AuthorityMetadataSource.CACHE && endpointMetadataResult?.source !== AuthorityMetadataSource.CACHE) {
      metadataEntity.expiresAt = generateAuthorityMetadataExpiresAt();
      metadataEntity.canonical_authority = this.canonicalAuthority;
    }
    const cacheKey = this.cacheManager.generateAuthorityMetadataCacheKey(metadataEntity.preferred_cache);
    this.cacheManager.setAuthorityMetadata(cacheKey, metadataEntity);
    this.metadata = metadataEntity;
  }
  /**
   * Update AuthorityMetadataEntity with new endpoints and return where the information came from
   * @param metadataEntity
   */
  updateEndpointMetadata(metadataEntity) {
    return __async(this, null, function* () {
      this.performanceClient?.addQueueMeasurement(PerformanceEvents.AuthorityUpdateEndpointMetadata, this.correlationId);
      const localMetadata = this.updateEndpointMetadataFromLocalSources(metadataEntity);
      if (localMetadata) {
        if (localMetadata.source === AuthorityMetadataSource.HARDCODED_VALUES) {
          if (this.authorityOptions.azureRegionConfiguration?.azureRegion) {
            if (localMetadata.metadata) {
              const hardcodedMetadata = yield invokeAsync(this.updateMetadataWithRegionalInformation.bind(this), PerformanceEvents.AuthorityUpdateMetadataWithRegionalInformation, this.logger, this.performanceClient, this.correlationId)(localMetadata.metadata);
              updateAuthorityEndpointMetadata(metadataEntity, hardcodedMetadata, false);
              metadataEntity.canonical_authority = this.canonicalAuthority;
            }
          }
        }
        return localMetadata.source;
      }
      let metadata = yield invokeAsync(this.getEndpointMetadataFromNetwork.bind(this), PerformanceEvents.AuthorityGetEndpointMetadataFromNetwork, this.logger, this.performanceClient, this.correlationId)();
      if (metadata) {
        if (this.authorityOptions.azureRegionConfiguration?.azureRegion) {
          metadata = yield invokeAsync(this.updateMetadataWithRegionalInformation.bind(this), PerformanceEvents.AuthorityUpdateMetadataWithRegionalInformation, this.logger, this.performanceClient, this.correlationId)(metadata);
        }
        updateAuthorityEndpointMetadata(metadataEntity, metadata, true);
        return AuthorityMetadataSource.NETWORK;
      } else {
        throw createClientAuthError(openIdConfigError, this.defaultOpenIdConfigurationEndpoint);
      }
    });
  }
  /**
   * Updates endpoint metadata from local sources and returns where the information was retrieved from and the metadata config
   * response if the source is hardcoded metadata
   * @param metadataEntity
   * @returns
   */
  updateEndpointMetadataFromLocalSources(metadataEntity) {
    this.logger.verbose("Attempting to get endpoint metadata from authority configuration");
    const configMetadata = this.getEndpointMetadataFromConfig();
    if (configMetadata) {
      this.logger.verbose("Found endpoint metadata in authority configuration");
      updateAuthorityEndpointMetadata(metadataEntity, configMetadata, false);
      return {
        source: AuthorityMetadataSource.CONFIG
      };
    }
    this.logger.verbose("Did not find endpoint metadata in the config... Attempting to get endpoint metadata from the hardcoded values.");
    if (this.authorityOptions.skipAuthorityMetadataCache) {
      this.logger.verbose("Skipping hardcoded metadata cache since skipAuthorityMetadataCache is set to true. Attempting to get endpoint metadata from the network metadata cache.");
    } else {
      const hardcodedMetadata = this.getEndpointMetadataFromHardcodedValues();
      if (hardcodedMetadata) {
        updateAuthorityEndpointMetadata(metadataEntity, hardcodedMetadata, false);
        return {
          source: AuthorityMetadataSource.HARDCODED_VALUES,
          metadata: hardcodedMetadata
        };
      } else {
        this.logger.verbose("Did not find endpoint metadata in hardcoded values... Attempting to get endpoint metadata from the network metadata cache.");
      }
    }
    const metadataEntityExpired = isAuthorityMetadataExpired(metadataEntity);
    if (this.isAuthoritySameType(metadataEntity) && metadataEntity.endpointsFromNetwork && !metadataEntityExpired) {
      this.logger.verbose("Found endpoint metadata in the cache.");
      return {
        source: AuthorityMetadataSource.CACHE
      };
    } else if (metadataEntityExpired) {
      this.logger.verbose("The metadata entity is expired.");
    }
    return null;
  }
  /**
   * Compares the number of url components after the domain to determine if the cached
   * authority metadata can be used for the requested authority. Protects against same domain different
   * authority such as login.microsoftonline.com/tenant and login.microsoftonline.com/tfp/tenant/policy
   * @param metadataEntity
   */
  isAuthoritySameType(metadataEntity) {
    const cachedAuthorityUrl = new UrlString(metadataEntity.canonical_authority);
    const cachedParts = cachedAuthorityUrl.getUrlComponents().PathSegments;
    return cachedParts.length === this.canonicalAuthorityUrlComponents.PathSegments.length;
  }
  /**
   * Parse authorityMetadata config option
   */
  getEndpointMetadataFromConfig() {
    if (this.authorityOptions.authorityMetadata) {
      try {
        return JSON.parse(this.authorityOptions.authorityMetadata);
      } catch (e) {
        throw createClientConfigurationError(invalidAuthorityMetadata);
      }
    }
    return null;
  }
  /**
   * Gets OAuth endpoints from the given OpenID configuration endpoint.
   *
   * @param hasHardcodedMetadata boolean
   */
  getEndpointMetadataFromNetwork() {
    return __async(this, null, function* () {
      this.performanceClient?.addQueueMeasurement(PerformanceEvents.AuthorityGetEndpointMetadataFromNetwork, this.correlationId);
      const options = {};
      const openIdConfigurationEndpoint = this.defaultOpenIdConfigurationEndpoint;
      this.logger.verbose(`Authority.getEndpointMetadataFromNetwork: attempting to retrieve OAuth endpoints from ${openIdConfigurationEndpoint}`);
      try {
        const response = yield this.networkInterface.sendGetRequestAsync(openIdConfigurationEndpoint, options);
        const isValidResponse = isOpenIdConfigResponse(response.body);
        if (isValidResponse) {
          return response.body;
        } else {
          this.logger.verbose(`Authority.getEndpointMetadataFromNetwork: could not parse response as OpenID configuration`);
          return null;
        }
      } catch (e) {
        this.logger.verbose(`Authority.getEndpointMetadataFromNetwork: ${e}`);
        return null;
      }
    });
  }
  /**
   * Get OAuth endpoints for common authorities.
   */
  getEndpointMetadataFromHardcodedValues() {
    if (this.hostnameAndPort in EndpointMetadata) {
      return EndpointMetadata[this.hostnameAndPort];
    }
    return null;
  }
  /**
   * Update the retrieved metadata with regional information.
   * User selected Azure region will be used if configured.
   */
  updateMetadataWithRegionalInformation(metadata) {
    return __async(this, null, function* () {
      this.performanceClient?.addQueueMeasurement(PerformanceEvents.AuthorityUpdateMetadataWithRegionalInformation, this.correlationId);
      const userConfiguredAzureRegion = this.authorityOptions.azureRegionConfiguration?.azureRegion;
      if (userConfiguredAzureRegion) {
        if (userConfiguredAzureRegion !== Constants.AZURE_REGION_AUTO_DISCOVER_FLAG) {
          this.regionDiscoveryMetadata.region_outcome = RegionDiscoveryOutcomes.CONFIGURED_NO_AUTO_DETECTION;
          this.regionDiscoveryMetadata.region_used = userConfiguredAzureRegion;
          return _Authority.replaceWithRegionalInformation(metadata, userConfiguredAzureRegion);
        }
        const autodetectedRegionName = yield invokeAsync(this.regionDiscovery.detectRegion.bind(this.regionDiscovery), PerformanceEvents.RegionDiscoveryDetectRegion, this.logger, this.performanceClient, this.correlationId)(this.authorityOptions.azureRegionConfiguration?.environmentRegion, this.regionDiscoveryMetadata);
        if (autodetectedRegionName) {
          this.regionDiscoveryMetadata.region_outcome = RegionDiscoveryOutcomes.AUTO_DETECTION_REQUESTED_SUCCESSFUL;
          this.regionDiscoveryMetadata.region_used = autodetectedRegionName;
          return _Authority.replaceWithRegionalInformation(metadata, autodetectedRegionName);
        }
        this.regionDiscoveryMetadata.region_outcome = RegionDiscoveryOutcomes.AUTO_DETECTION_REQUESTED_FAILED;
      }
      return metadata;
    });
  }
  /**
   * Updates the AuthorityMetadataEntity with new aliases, preferred_network and preferred_cache
   * and returns where the information was retrieved from
   * @param metadataEntity
   * @returns AuthorityMetadataSource
   */
  updateCloudDiscoveryMetadata(metadataEntity) {
    return __async(this, null, function* () {
      this.performanceClient?.addQueueMeasurement(PerformanceEvents.AuthorityUpdateCloudDiscoveryMetadata, this.correlationId);
      const localMetadataSource = this.updateCloudDiscoveryMetadataFromLocalSources(metadataEntity);
      if (localMetadataSource) {
        return localMetadataSource;
      }
      const metadata = yield invokeAsync(this.getCloudDiscoveryMetadataFromNetwork.bind(this), PerformanceEvents.AuthorityGetCloudDiscoveryMetadataFromNetwork, this.logger, this.performanceClient, this.correlationId)();
      if (metadata) {
        updateCloudDiscoveryMetadata(metadataEntity, metadata, true);
        return AuthorityMetadataSource.NETWORK;
      }
      throw createClientConfigurationError(untrustedAuthority);
    });
  }
  updateCloudDiscoveryMetadataFromLocalSources(metadataEntity) {
    this.logger.verbose("Attempting to get cloud discovery metadata  from authority configuration");
    this.logger.verbosePii(`Known Authorities: ${this.authorityOptions.knownAuthorities || Constants.NOT_APPLICABLE}`);
    this.logger.verbosePii(`Authority Metadata: ${this.authorityOptions.authorityMetadata || Constants.NOT_APPLICABLE}`);
    this.logger.verbosePii(`Canonical Authority: ${metadataEntity.canonical_authority || Constants.NOT_APPLICABLE}`);
    const metadata = this.getCloudDiscoveryMetadataFromConfig();
    if (metadata) {
      this.logger.verbose("Found cloud discovery metadata in authority configuration");
      updateCloudDiscoveryMetadata(metadataEntity, metadata, false);
      return AuthorityMetadataSource.CONFIG;
    }
    this.logger.verbose("Did not find cloud discovery metadata in the config... Attempting to get cloud discovery metadata from the hardcoded values.");
    if (this.options.skipAuthorityMetadataCache) {
      this.logger.verbose("Skipping hardcoded cloud discovery metadata cache since skipAuthorityMetadataCache is set to true. Attempting to get cloud discovery metadata from the network metadata cache.");
    } else {
      const hardcodedMetadata = getCloudDiscoveryMetadataFromHardcodedValues(this.hostnameAndPort);
      if (hardcodedMetadata) {
        this.logger.verbose("Found cloud discovery metadata from hardcoded values.");
        updateCloudDiscoveryMetadata(metadataEntity, hardcodedMetadata, false);
        return AuthorityMetadataSource.HARDCODED_VALUES;
      }
      this.logger.verbose("Did not find cloud discovery metadata in hardcoded values... Attempting to get cloud discovery metadata from the network metadata cache.");
    }
    const metadataEntityExpired = isAuthorityMetadataExpired(metadataEntity);
    if (this.isAuthoritySameType(metadataEntity) && metadataEntity.aliasesFromNetwork && !metadataEntityExpired) {
      this.logger.verbose("Found cloud discovery metadata in the cache.");
      return AuthorityMetadataSource.CACHE;
    } else if (metadataEntityExpired) {
      this.logger.verbose("The metadata entity is expired.");
    }
    return null;
  }
  /**
   * Parse cloudDiscoveryMetadata config or check knownAuthorities
   */
  getCloudDiscoveryMetadataFromConfig() {
    if (this.authorityType === AuthorityType.Ciam) {
      this.logger.verbose("CIAM authorities do not support cloud discovery metadata, generate the aliases from authority host.");
      return _Authority.createCloudDiscoveryMetadataFromHost(this.hostnameAndPort);
    }
    if (this.authorityOptions.cloudDiscoveryMetadata) {
      this.logger.verbose("The cloud discovery metadata has been provided as a network response, in the config.");
      try {
        this.logger.verbose("Attempting to parse the cloud discovery metadata.");
        const parsedResponse = JSON.parse(this.authorityOptions.cloudDiscoveryMetadata);
        const metadata = getCloudDiscoveryMetadataFromNetworkResponse(parsedResponse.metadata, this.hostnameAndPort);
        this.logger.verbose("Parsed the cloud discovery metadata.");
        if (metadata) {
          this.logger.verbose("There is returnable metadata attached to the parsed cloud discovery metadata.");
          return metadata;
        } else {
          this.logger.verbose("There is no metadata attached to the parsed cloud discovery metadata.");
        }
      } catch (e) {
        this.logger.verbose("Unable to parse the cloud discovery metadata. Throwing Invalid Cloud Discovery Metadata Error.");
        throw createClientConfigurationError(invalidCloudDiscoveryMetadata);
      }
    }
    if (this.isInKnownAuthorities()) {
      this.logger.verbose("The host is included in knownAuthorities. Creating new cloud discovery metadata from the host.");
      return _Authority.createCloudDiscoveryMetadataFromHost(this.hostnameAndPort);
    }
    return null;
  }
  /**
   * Called to get metadata from network if CloudDiscoveryMetadata was not populated by config
   *
   * @param hasHardcodedMetadata boolean
   */
  getCloudDiscoveryMetadataFromNetwork() {
    return __async(this, null, function* () {
      this.performanceClient?.addQueueMeasurement(PerformanceEvents.AuthorityGetCloudDiscoveryMetadataFromNetwork, this.correlationId);
      const instanceDiscoveryEndpoint = `${Constants.AAD_INSTANCE_DISCOVERY_ENDPT}${this.canonicalAuthority}oauth2/v2.0/authorize`;
      const options = {};
      let match = null;
      try {
        const response = yield this.networkInterface.sendGetRequestAsync(instanceDiscoveryEndpoint, options);
        let typedResponseBody;
        let metadata;
        if (isCloudInstanceDiscoveryResponse(response.body)) {
          typedResponseBody = response.body;
          metadata = typedResponseBody.metadata;
          this.logger.verbosePii(`tenant_discovery_endpoint is: ${typedResponseBody.tenant_discovery_endpoint}`);
        } else if (isCloudInstanceDiscoveryErrorResponse(response.body)) {
          this.logger.warning(`A CloudInstanceDiscoveryErrorResponse was returned. The cloud instance discovery network request's status code is: ${response.status}`);
          typedResponseBody = response.body;
          if (typedResponseBody.error === Constants.INVALID_INSTANCE) {
            this.logger.error("The CloudInstanceDiscoveryErrorResponse error is invalid_instance.");
            return null;
          }
          this.logger.warning(`The CloudInstanceDiscoveryErrorResponse error is ${typedResponseBody.error}`);
          this.logger.warning(`The CloudInstanceDiscoveryErrorResponse error description is ${typedResponseBody.error_description}`);
          this.logger.warning("Setting the value of the CloudInstanceDiscoveryMetadata (returned from the network) to []");
          metadata = [];
        } else {
          this.logger.error("AAD did not return a CloudInstanceDiscoveryResponse or CloudInstanceDiscoveryErrorResponse");
          return null;
        }
        this.logger.verbose("Attempting to find a match between the developer's authority and the CloudInstanceDiscoveryMetadata returned from the network request.");
        match = getCloudDiscoveryMetadataFromNetworkResponse(metadata, this.hostnameAndPort);
      } catch (error) {
        if (error instanceof AuthError) {
          this.logger.error(`There was a network error while attempting to get the cloud discovery instance metadata.
Error: ${error.errorCode}
Error Description: ${error.errorMessage}`);
        } else {
          const typedError = error;
          this.logger.error(`A non-MSALJS error was thrown while attempting to get the cloud instance discovery metadata.
Error: ${typedError.name}
Error Description: ${typedError.message}`);
        }
        return null;
      }
      if (!match) {
        this.logger.warning("The developer's authority was not found within the CloudInstanceDiscoveryMetadata returned from the network request.");
        this.logger.verbose("Creating custom Authority for custom domain scenario.");
        match = _Authority.createCloudDiscoveryMetadataFromHost(this.hostnameAndPort);
      }
      return match;
    });
  }
  /**
   * Helper function to determine if this host is included in the knownAuthorities config option
   */
  isInKnownAuthorities() {
    const matches = this.authorityOptions.knownAuthorities.filter((authority) => {
      return authority && UrlString.getDomainFromUrl(authority).toLowerCase() === this.hostnameAndPort;
    });
    return matches.length > 0;
  }
  /**
   * helper function to populate the authority based on azureCloudOptions
   * @param authorityString
   * @param azureCloudOptions
   */
  static generateAuthority(authorityString, azureCloudOptions) {
    let authorityAzureCloudInstance;
    if (azureCloudOptions && azureCloudOptions.azureCloudInstance !== AzureCloudInstance.None) {
      const tenant = azureCloudOptions.tenant ? azureCloudOptions.tenant : Constants.DEFAULT_COMMON_TENANT;
      authorityAzureCloudInstance = `${azureCloudOptions.azureCloudInstance}/${tenant}/`;
    }
    return authorityAzureCloudInstance ? authorityAzureCloudInstance : authorityString;
  }
  /**
   * Creates cloud discovery metadata object from a given host
   * @param host
   */
  static createCloudDiscoveryMetadataFromHost(host) {
    return {
      preferred_network: host,
      preferred_cache: host,
      aliases: [host]
    };
  }
  /**
   * helper function to generate environment from authority object
   */
  getPreferredCache() {
    if (this.managedIdentity) {
      return Constants.DEFAULT_AUTHORITY_HOST;
    } else if (this.discoveryComplete()) {
      return this.metadata.preferred_cache;
    } else {
      throw createClientAuthError(endpointResolutionError);
    }
  }
  /**
   * Returns whether or not the provided host is an alias of this authority instance
   * @param host
   */
  isAlias(host) {
    return this.metadata.aliases.indexOf(host) > -1;
  }
  /**
   * Returns whether or not the provided host is an alias of a known Microsoft authority for purposes of endpoint discovery
   * @param host
   */
  isAliasOfKnownMicrosoftAuthority(host) {
    return InstanceDiscoveryMetadataAliases.has(host);
  }
  /**
   * Checks whether the provided host is that of a public cloud authority
   *
   * @param authority string
   * @returns bool
   */
  static isPublicCloudAuthority(host) {
    return Constants.KNOWN_PUBLIC_CLOUDS.indexOf(host) >= 0;
  }
  /**
   * Rebuild the authority string with the region
   *
   * @param host string
   * @param region string
   */
  static buildRegionalAuthorityString(host, region, queryString) {
    const authorityUrlInstance = new UrlString(host);
    authorityUrlInstance.validateAsUri();
    const authorityUrlParts = authorityUrlInstance.getUrlComponents();
    let hostNameAndPort = `${region}.${authorityUrlParts.HostNameAndPort}`;
    if (this.isPublicCloudAuthority(authorityUrlParts.HostNameAndPort)) {
      hostNameAndPort = `${region}.${Constants.REGIONAL_AUTH_PUBLIC_CLOUD_SUFFIX}`;
    }
    const url = UrlString.constructAuthorityUriFromObject(__spreadProps(__spreadValues({}, authorityUrlInstance.getUrlComponents()), {
      HostNameAndPort: hostNameAndPort
    })).urlString;
    if (queryString) return `${url}?${queryString}`;
    return url;
  }
  /**
   * Replace the endpoints in the metadata object with their regional equivalents.
   *
   * @param metadata OpenIdConfigResponse
   * @param azureRegion string
   */
  static replaceWithRegionalInformation(metadata, azureRegion) {
    const regionalMetadata = __spreadValues({}, metadata);
    regionalMetadata.authorization_endpoint = _Authority.buildRegionalAuthorityString(regionalMetadata.authorization_endpoint, azureRegion);
    regionalMetadata.token_endpoint = _Authority.buildRegionalAuthorityString(regionalMetadata.token_endpoint, azureRegion);
    if (regionalMetadata.end_session_endpoint) {
      regionalMetadata.end_session_endpoint = _Authority.buildRegionalAuthorityString(regionalMetadata.end_session_endpoint, azureRegion);
    }
    return regionalMetadata;
  }
  /**
   * Transform CIAM_AUTHORIY as per the below rules:
   * If no path segments found and it is a CIAM authority (hostname ends with .ciamlogin.com), then transform it
   *
   * NOTE: The transformation path should go away once STS supports CIAM with the format: `tenantIdorDomain.ciamlogin.com`
   * `ciamlogin.com` can also change in the future and we should accommodate the same
   *
   * @param authority
   */
  static transformCIAMAuthority(authority) {
    let ciamAuthority = authority;
    const authorityUrl = new UrlString(authority);
    const authorityUrlComponents = authorityUrl.getUrlComponents();
    if (authorityUrlComponents.PathSegments.length === 0 && authorityUrlComponents.HostNameAndPort.endsWith(Constants.CIAM_AUTH_URL)) {
      const tenantIdOrDomain = authorityUrlComponents.HostNameAndPort.split(".")[0];
      ciamAuthority = `${ciamAuthority}${tenantIdOrDomain}${Constants.AAD_TENANT_DOMAIN_SUFFIX}`;
    }
    return ciamAuthority;
  }
};
Authority.reservedTenantDomains = /* @__PURE__ */ new Set(["{tenant}", "{tenantid}", AADAuthorityConstants.COMMON, AADAuthorityConstants.CONSUMERS, AADAuthorityConstants.ORGANIZATIONS]);

// node_modules/@azure/msal-common/dist/error/NetworkError.mjs
var NetworkError = class _NetworkError extends AuthError {
  constructor(error, httpStatus, responseHeaders) {
    super(error.errorCode, error.errorMessage, error.subError);
    Object.setPrototypeOf(this, _NetworkError.prototype);
    this.name = "NetworkError";
    this.error = error;
    this.httpStatus = httpStatus;
    this.responseHeaders = responseHeaders;
  }
};
function createNetworkError(error, httpStatus, responseHeaders) {
  return new NetworkError(error, httpStatus, responseHeaders);
}

// node_modules/@azure/msal-common/dist/error/InteractionRequiredAuthErrorCodes.mjs
var noTokensFound = "no_tokens_found";
var nativeAccountUnavailable = "native_account_unavailable";
var refreshTokenExpired = "refresh_token_expired";
var badToken = "bad_token";

// node_modules/@azure/msal-common/dist/error/InteractionRequiredAuthError.mjs
var InteractionRequiredAuthErrorMessages = {
  [noTokensFound]: "No refresh token found in the cache. Please sign-in.",
  [nativeAccountUnavailable]: "The requested account is not available in the native broker. It may have been deleted or logged out. Please sign-in again using an interactive API.",
  [refreshTokenExpired]: "Refresh token has expired.",
  [badToken]: "Identity provider returned bad_token due to an expired or invalid refresh token. Please invoke an interactive API to resolve."
};
var InteractionRequiredAuthErrorMessage = {
  noTokensFoundError: {
    code: noTokensFound,
    desc: InteractionRequiredAuthErrorMessages[noTokensFound]
  },
  native_account_unavailable: {
    code: nativeAccountUnavailable,
    desc: InteractionRequiredAuthErrorMessages[nativeAccountUnavailable]
  },
  bad_token: {
    code: badToken,
    desc: InteractionRequiredAuthErrorMessages[badToken]
  }
};

// node_modules/@azure/msal-common/dist/network/INetworkModule.mjs
var StubbedNetworkModule = {
  sendGetRequestAsync: () => {
    return Promise.reject(createClientAuthError(methodNotImplemented));
  },
  sendPostRequestAsync: () => {
    return Promise.reject(createClientAuthError(methodNotImplemented));
  }
};

// node_modules/@azure/msal-common/dist/error/JoseHeaderErrorCodes.mjs
var missingKidError = "missing_kid_error";
var missingAlgError = "missing_alg_error";

// node_modules/@azure/msal-common/dist/error/JoseHeaderError.mjs
var JoseHeaderErrorMessages = {
  [missingKidError]: "The JOSE Header for the requested JWT, JWS or JWK object requires a keyId to be configured as the 'kid' header claim. No 'kid' value was provided.",
  [missingAlgError]: "The JOSE Header for the requested JWT, JWS or JWK object requires an algorithm to be specified as the 'alg' header claim. No 'alg' value was provided."
};
var JoseHeaderError = class _JoseHeaderError extends AuthError {
  constructor(errorCode, errorMessage) {
    super(errorCode, errorMessage);
    this.name = "JoseHeaderError";
    Object.setPrototypeOf(this, _JoseHeaderError.prototype);
  }
};
function createJoseHeaderError(code) {
  return new JoseHeaderError(code, JoseHeaderErrorMessages[code]);
}

// node_modules/@azure/msal-common/dist/crypto/JoseHeader.mjs
var JoseHeader = class _JoseHeader {
  constructor(options) {
    this.typ = options.typ;
    this.alg = options.alg;
    this.kid = options.kid;
  }
  /**
   * Builds SignedHttpRequest formatted JOSE Header from the
   * JOSE Header options provided or previously set on the object and returns
   * the stringified header object.
   * Throws if keyId or algorithm aren't provided since they are required for Access Token Binding.
   * @param shrHeaderOptions
   * @returns
   */
  static getShrHeaderString(shrHeaderOptions) {
    if (!shrHeaderOptions.kid) {
      throw createJoseHeaderError(missingKidError);
    }
    if (!shrHeaderOptions.alg) {
      throw createJoseHeaderError(missingAlgError);
    }
    const shrHeader = new _JoseHeader({
      // Access Token PoP headers must have type pop, but the type header can be overriden for special cases
      typ: shrHeaderOptions.typ || JsonWebTokenTypes.Pop,
      kid: shrHeaderOptions.kid,
      alg: shrHeaderOptions.alg
    });
    return JSON.stringify(shrHeader);
  }
};

// node_modules/@azure/msal-common/dist/telemetry/performance/StubPerformanceClient.mjs
var StubPerformanceMeasurement = class {
  startMeasurement() {
    return;
  }
  endMeasurement() {
    return;
  }
  flushMeasurement() {
    return null;
  }
};
var StubPerformanceClient = class {
  generateId() {
    return "callback-id";
  }
  startMeasurement(measureName, correlationId) {
    return {
      end: () => null,
      discard: () => {
      },
      add: () => {
      },
      increment: () => {
      },
      event: {
        eventId: this.generateId(),
        status: PerformanceEventStatus.InProgress,
        authority: "",
        libraryName: "",
        libraryVersion: "",
        clientId: "",
        name: measureName,
        startTimeMs: Date.now(),
        correlationId: correlationId || ""
      },
      measurement: new StubPerformanceMeasurement()
    };
  }
  startPerformanceMeasurement() {
    return new StubPerformanceMeasurement();
  }
  calculateQueuedTime() {
    return 0;
  }
  addQueueMeasurement() {
    return;
  }
  setPreQueueTime() {
    return;
  }
  endMeasurement() {
    return null;
  }
  discardMeasurements() {
    return;
  }
  removePerformanceCallback() {
    return true;
  }
  addPerformanceCallback() {
    return "";
  }
  emitEvents() {
    return;
  }
  addFields() {
    return;
  }
  incrementFields() {
    return;
  }
  cacheEventByCorrelationId() {
    return;
  }
};

// node_modules/@azure/msal-browser/dist/error/BrowserAuthErrorCodes.mjs
var pkceNotCreated = "pkce_not_created";
var cryptoNonExistent = "crypto_nonexistent";
var emptyNavigateUri = "empty_navigate_uri";
var hashEmptyError = "hash_empty_error";
var noStateInHash = "no_state_in_hash";
var hashDoesNotContainKnownProperties = "hash_does_not_contain_known_properties";
var unableToParseState = "unable_to_parse_state";
var stateInteractionTypeMismatch = "state_interaction_type_mismatch";
var interactionInProgress = "interaction_in_progress";
var popupWindowError = "popup_window_error";
var emptyWindowError = "empty_window_error";
var userCancelled = "user_cancelled";
var monitorPopupTimeout = "monitor_popup_timeout";
var monitorWindowTimeout = "monitor_window_timeout";
var redirectInIframe = "redirect_in_iframe";
var blockIframeReload = "block_iframe_reload";
var blockNestedPopups = "block_nested_popups";
var iframeClosedPrematurely = "iframe_closed_prematurely";
var silentLogoutUnsupported = "silent_logout_unsupported";
var noAccountError = "no_account_error";
var silentPromptValueError = "silent_prompt_value_error";
var noTokenRequestCacheError = "no_token_request_cache_error";
var unableToParseTokenRequestCacheError = "unable_to_parse_token_request_cache_error";
var noCachedAuthorityError = "no_cached_authority_error";
var authRequestNotSetError = "auth_request_not_set_error";
var invalidCacheType = "invalid_cache_type";
var nonBrowserEnvironment = "non_browser_environment";
var databaseNotOpen = "database_not_open";
var noNetworkConnectivity2 = "no_network_connectivity";
var postRequestFailed2 = "post_request_failed";
var getRequestFailed = "get_request_failed";
var failedToParseResponse = "failed_to_parse_response";
var unableToLoadToken = "unable_to_load_token";
var cryptoKeyNotFound = "crypto_key_not_found";
var authCodeRequired = "auth_code_required";
var authCodeOrNativeAccountIdRequired = "auth_code_or_nativeAccountId_required";
var spaCodeAndNativeAccountIdPresent = "spa_code_and_nativeAccountId_present";
var databaseUnavailable = "database_unavailable";
var unableToAcquireTokenFromNativePlatform = "unable_to_acquire_token_from_native_platform";
var nativeHandshakeTimeout = "native_handshake_timeout";
var nativeExtensionNotInstalled = "native_extension_not_installed";
var nativeConnectionNotEstablished = "native_connection_not_established";
var uninitializedPublicClientApplication = "uninitialized_public_client_application";
var nativePromptNotSupported = "native_prompt_not_supported";
var invalidBase64String = "invalid_base64_string";
var invalidPopTokenRequest = "invalid_pop_token_request";
var failedToBuildHeaders = "failed_to_build_headers";
var failedToParseHeaders = "failed_to_parse_headers";

// node_modules/@azure/msal-browser/dist/error/BrowserAuthError.mjs
var ErrorLink = "For more visit: aka.ms/msaljs/browser-errors";
var BrowserAuthErrorMessages = {
  [pkceNotCreated]: "The PKCE code challenge and verifier could not be generated.",
  [cryptoNonExistent]: "The crypto object or function is not available.",
  [emptyNavigateUri]: "Navigation URI is empty. Please check stack trace for more info.",
  [hashEmptyError]: `Hash value cannot be processed because it is empty. Please verify that your redirectUri is not clearing the hash. ${ErrorLink}`,
  [noStateInHash]: "Hash does not contain state. Please verify that the request originated from msal.",
  [hashDoesNotContainKnownProperties]: `Hash does not contain known properites. Please verify that your redirectUri is not changing the hash.  ${ErrorLink}`,
  [unableToParseState]: "Unable to parse state. Please verify that the request originated from msal.",
  [stateInteractionTypeMismatch]: "Hash contains state but the interaction type does not match the caller.",
  [interactionInProgress]: `Interaction is currently in progress. Please ensure that this interaction has been completed before calling an interactive API.   ${ErrorLink}`,
  [popupWindowError]: "Error opening popup window. This can happen if you are using IE or if popups are blocked in the browser.",
  [emptyWindowError]: "window.open returned null or undefined window object.",
  [userCancelled]: "User cancelled the flow.",
  [monitorPopupTimeout]: `Token acquisition in popup failed due to timeout.  ${ErrorLink}`,
  [monitorWindowTimeout]: `Token acquisition in iframe failed due to timeout.  ${ErrorLink}`,
  [redirectInIframe]: "Redirects are not supported for iframed or brokered applications. Please ensure you are using MSAL.js in a top frame of the window if using the redirect APIs, or use the popup APIs.",
  [blockIframeReload]: `Request was blocked inside an iframe because MSAL detected an authentication response.  ${ErrorLink}`,
  [blockNestedPopups]: "Request was blocked inside a popup because MSAL detected it was running in a popup.",
  [iframeClosedPrematurely]: "The iframe being monitored was closed prematurely.",
  [silentLogoutUnsupported]: "Silent logout not supported. Please call logoutRedirect or logoutPopup instead.",
  [noAccountError]: "No account object provided to acquireTokenSilent and no active account has been set. Please call setActiveAccount or provide an account on the request.",
  [silentPromptValueError]: "The value given for the prompt value is not valid for silent requests - must be set to 'none' or 'no_session'.",
  [noTokenRequestCacheError]: "No token request found in cache.",
  [unableToParseTokenRequestCacheError]: "The cached token request could not be parsed.",
  [noCachedAuthorityError]: "No cached authority found.",
  [authRequestNotSetError]: "Auth Request not set. Please ensure initiateAuthRequest was called from the InteractionHandler",
  [invalidCacheType]: "Invalid cache type",
  [nonBrowserEnvironment]: "Login and token requests are not supported in non-browser environments.",
  [databaseNotOpen]: "Database is not open!",
  [noNetworkConnectivity2]: "No network connectivity. Check your internet connection.",
  [postRequestFailed2]: "Network request failed: If the browser threw a CORS error, check that the redirectUri is registered in the Azure App Portal as type 'SPA'",
  [getRequestFailed]: "Network request failed. Please check the network trace to determine root cause.",
  [failedToParseResponse]: "Failed to parse network response. Check network trace.",
  [unableToLoadToken]: "Error loading token to cache.",
  [cryptoKeyNotFound]: "Cryptographic Key or Keypair not found in browser storage.",
  [authCodeRequired]: "An authorization code must be provided (as the `code` property on the request) to this flow.",
  [authCodeOrNativeAccountIdRequired]: "An authorization code or nativeAccountId must be provided to this flow.",
  [spaCodeAndNativeAccountIdPresent]: "Request cannot contain both spa code and native account id.",
  [databaseUnavailable]: "IndexedDB, which is required for persistent cryptographic key storage, is unavailable. This may be caused by browser privacy features which block persistent storage in third-party contexts.",
  [unableToAcquireTokenFromNativePlatform]: `Unable to acquire token from native platform.  ${ErrorLink}`,
  [nativeHandshakeTimeout]: "Timed out while attempting to establish connection to browser extension",
  [nativeExtensionNotInstalled]: "Native extension is not installed. If you think this is a mistake call the initialize function.",
  [nativeConnectionNotEstablished]: `Connection to native platform has not been established. Please install a compatible browser extension and run initialize().  ${ErrorLink}`,
  [uninitializedPublicClientApplication]: `You must call and await the initialize function before attempting to call any other MSAL API.  ${ErrorLink}`,
  [nativePromptNotSupported]: "The provided prompt is not supported by the native platform. This request should be routed to the web based flow.",
  [invalidBase64String]: "Invalid base64 encoded string.",
  [invalidPopTokenRequest]: "Invalid PoP token request. The request should not have both a popKid value and signPopToken set to true.",
  [failedToBuildHeaders]: "Failed to build request headers object.",
  [failedToParseHeaders]: "Failed to parse response headers"
};
var BrowserAuthErrorMessage = {
  pkceNotGenerated: {
    code: pkceNotCreated,
    desc: BrowserAuthErrorMessages[pkceNotCreated]
  },
  cryptoDoesNotExist: {
    code: cryptoNonExistent,
    desc: BrowserAuthErrorMessages[cryptoNonExistent]
  },
  emptyNavigateUriError: {
    code: emptyNavigateUri,
    desc: BrowserAuthErrorMessages[emptyNavigateUri]
  },
  hashEmptyError: {
    code: hashEmptyError,
    desc: BrowserAuthErrorMessages[hashEmptyError]
  },
  hashDoesNotContainStateError: {
    code: noStateInHash,
    desc: BrowserAuthErrorMessages[noStateInHash]
  },
  hashDoesNotContainKnownPropertiesError: {
    code: hashDoesNotContainKnownProperties,
    desc: BrowserAuthErrorMessages[hashDoesNotContainKnownProperties]
  },
  unableToParseStateError: {
    code: unableToParseState,
    desc: BrowserAuthErrorMessages[unableToParseState]
  },
  stateInteractionTypeMismatchError: {
    code: stateInteractionTypeMismatch,
    desc: BrowserAuthErrorMessages[stateInteractionTypeMismatch]
  },
  interactionInProgress: {
    code: interactionInProgress,
    desc: BrowserAuthErrorMessages[interactionInProgress]
  },
  popupWindowError: {
    code: popupWindowError,
    desc: BrowserAuthErrorMessages[popupWindowError]
  },
  emptyWindowError: {
    code: emptyWindowError,
    desc: BrowserAuthErrorMessages[emptyWindowError]
  },
  userCancelledError: {
    code: userCancelled,
    desc: BrowserAuthErrorMessages[userCancelled]
  },
  monitorPopupTimeoutError: {
    code: monitorPopupTimeout,
    desc: BrowserAuthErrorMessages[monitorPopupTimeout]
  },
  monitorIframeTimeoutError: {
    code: monitorWindowTimeout,
    desc: BrowserAuthErrorMessages[monitorWindowTimeout]
  },
  redirectInIframeError: {
    code: redirectInIframe,
    desc: BrowserAuthErrorMessages[redirectInIframe]
  },
  blockTokenRequestsInHiddenIframeError: {
    code: blockIframeReload,
    desc: BrowserAuthErrorMessages[blockIframeReload]
  },
  blockAcquireTokenInPopupsError: {
    code: blockNestedPopups,
    desc: BrowserAuthErrorMessages[blockNestedPopups]
  },
  iframeClosedPrematurelyError: {
    code: iframeClosedPrematurely,
    desc: BrowserAuthErrorMessages[iframeClosedPrematurely]
  },
  silentLogoutUnsupportedError: {
    code: silentLogoutUnsupported,
    desc: BrowserAuthErrorMessages[silentLogoutUnsupported]
  },
  noAccountError: {
    code: noAccountError,
    desc: BrowserAuthErrorMessages[noAccountError]
  },
  silentPromptValueError: {
    code: silentPromptValueError,
    desc: BrowserAuthErrorMessages[silentPromptValueError]
  },
  noTokenRequestCacheError: {
    code: noTokenRequestCacheError,
    desc: BrowserAuthErrorMessages[noTokenRequestCacheError]
  },
  unableToParseTokenRequestCacheError: {
    code: unableToParseTokenRequestCacheError,
    desc: BrowserAuthErrorMessages[unableToParseTokenRequestCacheError]
  },
  noCachedAuthorityError: {
    code: noCachedAuthorityError,
    desc: BrowserAuthErrorMessages[noCachedAuthorityError]
  },
  authRequestNotSet: {
    code: authRequestNotSetError,
    desc: BrowserAuthErrorMessages[authRequestNotSetError]
  },
  invalidCacheType: {
    code: invalidCacheType,
    desc: BrowserAuthErrorMessages[invalidCacheType]
  },
  notInBrowserEnvironment: {
    code: nonBrowserEnvironment,
    desc: BrowserAuthErrorMessages[nonBrowserEnvironment]
  },
  databaseNotOpen: {
    code: databaseNotOpen,
    desc: BrowserAuthErrorMessages[databaseNotOpen]
  },
  noNetworkConnectivity: {
    code: noNetworkConnectivity2,
    desc: BrowserAuthErrorMessages[noNetworkConnectivity2]
  },
  postRequestFailed: {
    code: postRequestFailed2,
    desc: BrowserAuthErrorMessages[postRequestFailed2]
  },
  getRequestFailed: {
    code: getRequestFailed,
    desc: BrowserAuthErrorMessages[getRequestFailed]
  },
  failedToParseNetworkResponse: {
    code: failedToParseResponse,
    desc: BrowserAuthErrorMessages[failedToParseResponse]
  },
  unableToLoadTokenError: {
    code: unableToLoadToken,
    desc: BrowserAuthErrorMessages[unableToLoadToken]
  },
  signingKeyNotFoundInStorage: {
    code: cryptoKeyNotFound,
    desc: BrowserAuthErrorMessages[cryptoKeyNotFound]
  },
  authCodeRequired: {
    code: authCodeRequired,
    desc: BrowserAuthErrorMessages[authCodeRequired]
  },
  authCodeOrNativeAccountRequired: {
    code: authCodeOrNativeAccountIdRequired,
    desc: BrowserAuthErrorMessages[authCodeOrNativeAccountIdRequired]
  },
  spaCodeAndNativeAccountPresent: {
    code: spaCodeAndNativeAccountIdPresent,
    desc: BrowserAuthErrorMessages[spaCodeAndNativeAccountIdPresent]
  },
  databaseUnavailable: {
    code: databaseUnavailable,
    desc: BrowserAuthErrorMessages[databaseUnavailable]
  },
  unableToAcquireTokenFromNativePlatform: {
    code: unableToAcquireTokenFromNativePlatform,
    desc: BrowserAuthErrorMessages[unableToAcquireTokenFromNativePlatform]
  },
  nativeHandshakeTimeout: {
    code: nativeHandshakeTimeout,
    desc: BrowserAuthErrorMessages[nativeHandshakeTimeout]
  },
  nativeExtensionNotInstalled: {
    code: nativeExtensionNotInstalled,
    desc: BrowserAuthErrorMessages[nativeExtensionNotInstalled]
  },
  nativeConnectionNotEstablished: {
    code: nativeConnectionNotEstablished,
    desc: BrowserAuthErrorMessages[nativeConnectionNotEstablished]
  },
  uninitializedPublicClientApplication: {
    code: uninitializedPublicClientApplication,
    desc: BrowserAuthErrorMessages[uninitializedPublicClientApplication]
  },
  nativePromptNotSupported: {
    code: nativePromptNotSupported,
    desc: BrowserAuthErrorMessages[nativePromptNotSupported]
  },
  invalidBase64StringError: {
    code: invalidBase64String,
    desc: BrowserAuthErrorMessages[invalidBase64String]
  },
  invalidPopTokenRequest: {
    code: invalidPopTokenRequest,
    desc: BrowserAuthErrorMessages[invalidPopTokenRequest]
  }
};
var BrowserAuthError = class _BrowserAuthError extends AuthError {
  constructor(errorCode, subError) {
    super(errorCode, BrowserAuthErrorMessages[errorCode], subError);
    Object.setPrototypeOf(this, _BrowserAuthError.prototype);
    this.name = "BrowserAuthError";
  }
};
function createBrowserAuthError(errorCode, subError) {
  return new BrowserAuthError(errorCode, subError);
}

// node_modules/@azure/msal-browser/dist/utils/BrowserConstants.mjs
var BrowserConstants = {
  /**
   * Interaction in progress cache value
   */
  INTERACTION_IN_PROGRESS_VALUE: "interaction_in_progress",
  /**
   * Invalid grant error code
   */
  INVALID_GRANT_ERROR: "invalid_grant",
  /**
   * Default popup window width
   */
  POPUP_WIDTH: 483,
  /**
   * Default popup window height
   */
  POPUP_HEIGHT: 600,
  /**
   * Name of the popup window starts with
   */
  POPUP_NAME_PREFIX: "msal",
  /**
   * Default popup monitor poll interval in milliseconds
   */
  DEFAULT_POLL_INTERVAL_MS: 30,
  /**
   * Msal-browser SKU
   */
  MSAL_SKU: "msal.js.browser"
};
var BrowserCacheLocation = {
  LocalStorage: "localStorage",
  SessionStorage: "sessionStorage",
  MemoryStorage: "memoryStorage"
};
var HTTP_REQUEST_TYPE = {
  GET: "GET",
  POST: "POST"
};
var InteractionType;
(function(InteractionType2) {
  InteractionType2["Redirect"] = "redirect";
  InteractionType2["Popup"] = "popup";
  InteractionType2["Silent"] = "silent";
  InteractionType2["None"] = "none";
})(InteractionType || (InteractionType = {}));
var InteractionStatus = {
  /**
   * Initial status before interaction occurs
   */
  Startup: "startup",
  /**
   * Status set when all login calls occuring
   */
  Login: "login",
  /**
   * Status set when logout call occuring
   */
  Logout: "logout",
  /**
   * Status set for acquireToken calls
   */
  AcquireToken: "acquireToken",
  /**
   * Status set for ssoSilent calls
   */
  SsoSilent: "ssoSilent",
  /**
   * Status set when handleRedirect in progress
   */
  HandleRedirect: "handleRedirect",
  /**
   * Status set when interaction is complete
   */
  None: "none"
};
var KEY_FORMAT_JWK = "jwk";
var WrapperSKU = {
  React: "@azure/msal-react",
  Angular: "@azure/msal-angular"
};
var DB_NAME = "msal.db";
var DB_VERSION = 1;
var DB_TABLE_NAME = `${DB_NAME}.keys`;
var CacheLookupPolicy = {
  /*
   * acquireTokenSilent will attempt to retrieve an access token from the cache. If the access token is expired
   * or cannot be found the refresh token will be used to acquire a new one. Finally, if the refresh token
   * is expired acquireTokenSilent will attempt to acquire new access and refresh tokens.
   */
  Default: 0,
  /*
   * acquireTokenSilent will only look for access tokens in the cache. It will not attempt to renew access or
   * refresh tokens.
   */
  AccessToken: 1,
  /*
   * acquireTokenSilent will attempt to retrieve an access token from the cache. If the access token is expired or
   * cannot be found, the refresh token will be used to acquire a new one. If the refresh token is expired, it
   * will not be renewed and acquireTokenSilent will fail.
   */
  AccessTokenAndRefreshToken: 2,
  /*
   * acquireTokenSilent will not attempt to retrieve access tokens from the cache and will instead attempt to
   * exchange the cached refresh token for a new access token. If the refresh token is expired, it will not be
   * renewed and acquireTokenSilent will fail.
   */
  RefreshToken: 3,
  /*
   * acquireTokenSilent will not look in the cache for the access token. It will go directly to network with the
   * cached refresh token. If the refresh token is expired an attempt will be made to renew it. This is equivalent to
   * setting "forceRefresh: true".
   */
  RefreshTokenAndNetwork: 4,
  /*
   * acquireTokenSilent will attempt to renew both access and refresh tokens. It will not look in the cache. This will
   * always fail if 3rd party cookies are blocked by the browser.
   */
  Skip: 5
};
var iFrameRenewalPolicies = [CacheLookupPolicy.Default, CacheLookupPolicy.Skip, CacheLookupPolicy.RefreshTokenAndNetwork];
var LOG_LEVEL_CACHE_KEY = "msal.browser.log.level";
var LOG_PII_CACHE_KEY = "msal.browser.log.pii";

// node_modules/@azure/msal-browser/dist/encode/Base64Encode.mjs
function urlEncode(input) {
  return encodeURIComponent(base64Encode(input).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"));
}
function urlEncodeArr(inputArr) {
  return base64EncArr(inputArr).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function base64Encode(input) {
  return base64EncArr(new TextEncoder().encode(input));
}
function base64EncArr(aBytes) {
  const binString = Array.from(aBytes, (x) => String.fromCodePoint(x)).join("");
  return btoa(binString);
}

// node_modules/@azure/msal-browser/dist/encode/Base64Decode.mjs
function base64Decode(input) {
  return new TextDecoder().decode(base64DecToArr(input));
}
function base64DecToArr(base64String) {
  let encodedString = base64String.replace(/-/g, "+").replace(/_/g, "/");
  switch (encodedString.length % 4) {
    case 0:
      break;
    case 2:
      encodedString += "==";
      break;
    case 3:
      encodedString += "=";
      break;
    default:
      throw createBrowserAuthError(invalidBase64String);
  }
  const binString = atob(encodedString);
  return Uint8Array.from(binString, (m) => m.codePointAt(0) || 0);
}

// node_modules/@azure/msal-browser/dist/crypto/BrowserCrypto.mjs
var PKCS1_V15_KEYGEN_ALG = "RSASSA-PKCS1-v1_5";
var S256_HASH_ALG = "SHA-256";
var MODULUS_LENGTH = 2048;
var PUBLIC_EXPONENT = new Uint8Array([1, 0, 1]);
var UUID_CHARS = "0123456789abcdef";
var UINT32_ARR = new Uint32Array(1);
var SUBTLE_SUBERROR = "crypto_subtle_undefined";
var keygenAlgorithmOptions = {
  name: PKCS1_V15_KEYGEN_ALG,
  hash: S256_HASH_ALG,
  modulusLength: MODULUS_LENGTH,
  publicExponent: PUBLIC_EXPONENT
};
function validateCryptoAvailable(skipValidateSubtleCrypto) {
  if (!window) {
    throw createBrowserAuthError(nonBrowserEnvironment);
  }
  if (!window.crypto) {
    throw createBrowserAuthError(cryptoNonExistent);
  }
  if (!skipValidateSubtleCrypto && !window.crypto.subtle) {
    throw createBrowserAuthError(cryptoNonExistent, SUBTLE_SUBERROR);
  }
}
function sha256Digest(dataString, performanceClient, correlationId) {
  return __async(this, null, function* () {
    performanceClient?.addQueueMeasurement(PerformanceEvents.Sha256Digest, correlationId);
    const encoder = new TextEncoder();
    const data = encoder.encode(dataString);
    return window.crypto.subtle.digest(S256_HASH_ALG, data);
  });
}
function getRandomUint32() {
  window.crypto.getRandomValues(UINT32_ARR);
  return UINT32_ARR[0];
}
function createNewGuid() {
  const currentTimestamp = Date.now();
  const baseRand = getRandomUint32() * 1024 + (getRandomUint32() & 1023);
  const bytes = new Uint8Array(16);
  const randA = Math.trunc(baseRand / 2 ** 30);
  const randBHi = baseRand & 2 ** 30 - 1;
  const randBLo = getRandomUint32();
  bytes[0] = currentTimestamp / 2 ** 40;
  bytes[1] = currentTimestamp / 2 ** 32;
  bytes[2] = currentTimestamp / 2 ** 24;
  bytes[3] = currentTimestamp / 2 ** 16;
  bytes[4] = currentTimestamp / 2 ** 8;
  bytes[5] = currentTimestamp;
  bytes[6] = 112 | randA >>> 8;
  bytes[7] = randA;
  bytes[8] = 128 | randBHi >>> 24;
  bytes[9] = randBHi >>> 16;
  bytes[10] = randBHi >>> 8;
  bytes[11] = randBHi;
  bytes[12] = randBLo >>> 24;
  bytes[13] = randBLo >>> 16;
  bytes[14] = randBLo >>> 8;
  bytes[15] = randBLo;
  let text = "";
  for (let i = 0; i < bytes.length; i++) {
    text += UUID_CHARS.charAt(bytes[i] >>> 4);
    text += UUID_CHARS.charAt(bytes[i] & 15);
    if (i === 3 || i === 5 || i === 7 || i === 9) {
      text += "-";
    }
  }
  return text;
}
function generateKeyPair(extractable, usages) {
  return __async(this, null, function* () {
    return window.crypto.subtle.generateKey(keygenAlgorithmOptions, extractable, usages);
  });
}
function exportJwk(key) {
  return __async(this, null, function* () {
    return window.crypto.subtle.exportKey(KEY_FORMAT_JWK, key);
  });
}
function importJwk(key, extractable, usages) {
  return __async(this, null, function* () {
    return window.crypto.subtle.importKey(KEY_FORMAT_JWK, key, keygenAlgorithmOptions, extractable, usages);
  });
}
function sign(key, data) {
  return __async(this, null, function* () {
    return window.crypto.subtle.sign(keygenAlgorithmOptions, key, data);
  });
}
function hashString(plainText) {
  return __async(this, null, function* () {
    const hashBuffer = yield sha256Digest(plainText);
    const hashBytes = new Uint8Array(hashBuffer);
    return urlEncodeArr(hashBytes);
  });
}

// node_modules/@azure/msal-browser/dist/error/BrowserConfigurationAuthErrorCodes.mjs
var storageNotSupported = "storage_not_supported";
var stubbedPublicClientApplicationCalled = "stubbed_public_client_application_called";
var inMemRedirectUnavailable = "in_mem_redirect_unavailable";

// node_modules/@azure/msal-browser/dist/error/BrowserConfigurationAuthError.mjs
var BrowserConfigurationAuthErrorMessages = {
  [storageNotSupported]: "Given storage configuration option was not supported.",
  [stubbedPublicClientApplicationCalled]: "Stub instance of Public Client Application was called. If using msal-react, please ensure context is not used without a provider. For more visit: aka.ms/msaljs/browser-errors",
  [inMemRedirectUnavailable]: "Redirect cannot be supported. In-memory storage was selected and storeAuthStateInCookie=false, which would cause the library to be unable to handle the incoming hash. If you would like to use the redirect API, please use session/localStorage or set storeAuthStateInCookie=true."
};
var BrowserConfigurationAuthErrorMessage = {
  storageNotSupportedError: {
    code: storageNotSupported,
    desc: BrowserConfigurationAuthErrorMessages[storageNotSupported]
  },
  stubPcaInstanceCalled: {
    code: stubbedPublicClientApplicationCalled,
    desc: BrowserConfigurationAuthErrorMessages[stubbedPublicClientApplicationCalled]
  },
  inMemRedirectUnavailable: {
    code: inMemRedirectUnavailable,
    desc: BrowserConfigurationAuthErrorMessages[inMemRedirectUnavailable]
  }
};
var BrowserConfigurationAuthError = class _BrowserConfigurationAuthError extends AuthError {
  constructor(errorCode, errorMessage) {
    super(errorCode, errorMessage);
    this.name = "BrowserConfigurationAuthError";
    Object.setPrototypeOf(this, _BrowserConfigurationAuthError.prototype);
  }
};
function createBrowserConfigurationAuthError(errorCode) {
  return new BrowserConfigurationAuthError(errorCode, BrowserConfigurationAuthErrorMessages[errorCode]);
}

// node_modules/@azure/msal-browser/dist/utils/BrowserUtils.mjs
function clearHash(contentWindow) {
  contentWindow.location.hash = "";
  if (typeof contentWindow.history.replaceState === "function") {
    contentWindow.history.replaceState(null, "", `${contentWindow.location.origin}${contentWindow.location.pathname}${contentWindow.location.search}`);
  }
}
function replaceHash(url) {
  const urlParts = url.split("#");
  urlParts.shift();
  window.location.hash = urlParts.length > 0 ? urlParts.join("#") : "";
}
function isInIframe() {
  return window.parent !== window;
}
function isInPopup() {
  return typeof window !== "undefined" && !!window.opener && window.opener !== window && typeof window.name === "string" && window.name.indexOf(`${BrowserConstants.POPUP_NAME_PREFIX}.`) === 0;
}
function getCurrentUri() {
  return typeof window !== "undefined" && window.location ? window.location.href.split("?")[0].split("#")[0] : "";
}
function getHomepage() {
  const currentUrl = new UrlString(window.location.href);
  const urlComponents = currentUrl.getUrlComponents();
  return `${urlComponents.Protocol}//${urlComponents.HostNameAndPort}/`;
}
function blockReloadInHiddenIframes() {
  const isResponseHash = UrlString.hashContainsKnownProperties(window.location.hash);
  if (isResponseHash && isInIframe()) {
    throw createBrowserAuthError(blockIframeReload);
  }
}
function blockRedirectInIframe(allowRedirectInIframe) {
  if (isInIframe() && !allowRedirectInIframe) {
    throw createBrowserAuthError(redirectInIframe);
  }
}
function blockAcquireTokenInPopups() {
  if (isInPopup()) {
    throw createBrowserAuthError(blockNestedPopups);
  }
}
function blockNonBrowserEnvironment() {
  if (typeof window === "undefined") {
    throw createBrowserAuthError(nonBrowserEnvironment);
  }
}
function blockAPICallsBeforeInitialize(initialized) {
  if (!initialized) {
    throw createBrowserAuthError(uninitializedPublicClientApplication);
  }
}
function preflightCheck(initialized) {
  blockNonBrowserEnvironment();
  blockReloadInHiddenIframes();
  blockAcquireTokenInPopups();
  blockAPICallsBeforeInitialize(initialized);
}
function redirectPreflightCheck(initialized, config) {
  preflightCheck(initialized);
  blockRedirectInIframe(config.system.allowRedirectInIframe);
  if (config.cache.cacheLocation === BrowserCacheLocation.MemoryStorage && !config.cache.storeAuthStateInCookie) {
    throw createBrowserConfigurationAuthError(inMemRedirectUnavailable);
  }
}
function preconnect(authority) {
  const link = document.createElement("link");
  link.rel = "preconnect";
  link.href = new URL(authority).origin;
  link.crossOrigin = "anonymous";
  document.head.appendChild(link);
  window.setTimeout(() => {
    try {
      document.head.removeChild(link);
    } catch {
    }
  }, 1e4);
}
function createGuid() {
  return createNewGuid();
}

// node_modules/@azure/msal-browser/dist/navigation/NavigationClient.mjs
var NavigationClient = class _NavigationClient {
  /**
   * Navigates to other pages within the same web application
   * @param url
   * @param options
   */
  navigateInternal(url, options) {
    return _NavigationClient.defaultNavigateWindow(url, options);
  }
  /**
   * Navigates to other pages outside the web application i.e. the Identity Provider
   * @param url
   * @param options
   */
  navigateExternal(url, options) {
    return _NavigationClient.defaultNavigateWindow(url, options);
  }
  /**
   * Default navigation implementation invoked by the internal and external functions
   * @param url
   * @param options
   */
  static defaultNavigateWindow(url, options) {
    if (options.noHistory) {
      window.location.replace(url);
    } else {
      window.location.assign(url);
    }
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(true);
      }, options.timeout);
    });
  }
};

// node_modules/@azure/msal-browser/dist/network/FetchClient.mjs
var FetchClient = class {
  /**
   * Fetch Client for REST endpoints - Get request
   * @param url
   * @param headers
   * @param body
   */
  sendGetRequestAsync(url, options) {
    return __async(this, null, function* () {
      let response;
      let responseHeaders = {};
      let responseStatus = 0;
      const reqHeaders = getFetchHeaders(options);
      try {
        response = yield fetch(url, {
          method: HTTP_REQUEST_TYPE.GET,
          headers: reqHeaders
        });
      } catch (e) {
        throw createBrowserAuthError(window.navigator.onLine ? getRequestFailed : noNetworkConnectivity2);
      }
      responseHeaders = getHeaderDict(response.headers);
      try {
        responseStatus = response.status;
        return {
          headers: responseHeaders,
          body: yield response.json(),
          status: responseStatus
        };
      } catch (e) {
        throw createNetworkError(createBrowserAuthError(failedToParseResponse), responseStatus, responseHeaders);
      }
    });
  }
  /**
   * Fetch Client for REST endpoints - Post request
   * @param url
   * @param headers
   * @param body
   */
  sendPostRequestAsync(url, options) {
    return __async(this, null, function* () {
      const reqBody = options && options.body || "";
      const reqHeaders = getFetchHeaders(options);
      let response;
      let responseStatus = 0;
      let responseHeaders = {};
      try {
        response = yield fetch(url, {
          method: HTTP_REQUEST_TYPE.POST,
          headers: reqHeaders,
          body: reqBody
        });
      } catch (e) {
        throw createBrowserAuthError(window.navigator.onLine ? postRequestFailed2 : noNetworkConnectivity2);
      }
      responseHeaders = getHeaderDict(response.headers);
      try {
        responseStatus = response.status;
        return {
          headers: responseHeaders,
          body: yield response.json(),
          status: responseStatus
        };
      } catch (e) {
        throw createNetworkError(createBrowserAuthError(failedToParseResponse), responseStatus, responseHeaders);
      }
    });
  }
};
function getFetchHeaders(options) {
  try {
    const headers = new Headers();
    if (!(options && options.headers)) {
      return headers;
    }
    const optionsHeaders = options.headers;
    Object.entries(optionsHeaders).forEach(([key, value]) => {
      headers.append(key, value);
    });
    return headers;
  } catch (e) {
    throw createBrowserAuthError(failedToBuildHeaders);
  }
}
function getHeaderDict(headers) {
  try {
    const headerDict = {};
    headers.forEach((value, key) => {
      headerDict[key] = value;
    });
    return headerDict;
  } catch (e) {
    throw createBrowserAuthError(failedToParseHeaders);
  }
}

// node_modules/@azure/msal-browser/dist/config/Configuration.mjs
var DEFAULT_POPUP_TIMEOUT_MS = 6e4;
var DEFAULT_IFRAME_TIMEOUT_MS = 1e4;
var DEFAULT_REDIRECT_TIMEOUT_MS = 3e4;
var DEFAULT_NATIVE_BROKER_HANDSHAKE_TIMEOUT_MS = 2e3;
function buildConfiguration({
  auth: userInputAuth,
  cache: userInputCache,
  system: userInputSystem,
  telemetry: userInputTelemetry
}, isBrowserEnvironment) {
  const DEFAULT_AUTH_OPTIONS = {
    clientId: Constants.EMPTY_STRING,
    authority: `${Constants.DEFAULT_AUTHORITY}`,
    knownAuthorities: [],
    cloudDiscoveryMetadata: Constants.EMPTY_STRING,
    authorityMetadata: Constants.EMPTY_STRING,
    redirectUri: typeof window !== "undefined" ? getCurrentUri() : "",
    postLogoutRedirectUri: Constants.EMPTY_STRING,
    navigateToLoginRequestUrl: true,
    clientCapabilities: [],
    protocolMode: ProtocolMode.AAD,
    OIDCOptions: {
      serverResponseType: ServerResponseType.FRAGMENT,
      defaultScopes: [Constants.OPENID_SCOPE, Constants.PROFILE_SCOPE, Constants.OFFLINE_ACCESS_SCOPE]
    },
    azureCloudOptions: {
      azureCloudInstance: AzureCloudInstance.None,
      tenant: Constants.EMPTY_STRING
    },
    skipAuthorityMetadataCache: false,
    supportsNestedAppAuth: false,
    instanceAware: false
  };
  const DEFAULT_CACHE_OPTIONS = {
    cacheLocation: BrowserCacheLocation.SessionStorage,
    temporaryCacheLocation: BrowserCacheLocation.SessionStorage,
    storeAuthStateInCookie: false,
    secureCookies: false,
    // Default cache migration to true if cache location is localStorage since entries are preserved across tabs/windows. Migration has little to no benefit in sessionStorage and memoryStorage
    cacheMigrationEnabled: userInputCache && userInputCache.cacheLocation === BrowserCacheLocation.LocalStorage ? true : false,
    claimsBasedCachingEnabled: false
  };
  const DEFAULT_LOGGER_OPTIONS = {
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    loggerCallback: () => {
    },
    logLevel: LogLevel.Info,
    piiLoggingEnabled: false
  };
  const DEFAULT_BROWSER_SYSTEM_OPTIONS = __spreadProps(__spreadValues({}, DEFAULT_SYSTEM_OPTIONS), {
    loggerOptions: DEFAULT_LOGGER_OPTIONS,
    networkClient: isBrowserEnvironment ? new FetchClient() : StubbedNetworkModule,
    navigationClient: new NavigationClient(),
    loadFrameTimeout: 0,
    // If loadFrameTimeout is provided, use that as default.
    windowHashTimeout: userInputSystem?.loadFrameTimeout || DEFAULT_POPUP_TIMEOUT_MS,
    iframeHashTimeout: userInputSystem?.loadFrameTimeout || DEFAULT_IFRAME_TIMEOUT_MS,
    navigateFrameWait: 0,
    redirectNavigationTimeout: DEFAULT_REDIRECT_TIMEOUT_MS,
    asyncPopups: false,
    allowRedirectInIframe: false,
    allowPlatformBroker: false,
    nativeBrokerHandshakeTimeout: userInputSystem?.nativeBrokerHandshakeTimeout || DEFAULT_NATIVE_BROKER_HANDSHAKE_TIMEOUT_MS,
    pollIntervalMilliseconds: BrowserConstants.DEFAULT_POLL_INTERVAL_MS
  });
  const providedSystemOptions = __spreadProps(__spreadValues(__spreadValues({}, DEFAULT_BROWSER_SYSTEM_OPTIONS), userInputSystem), {
    loggerOptions: userInputSystem?.loggerOptions || DEFAULT_LOGGER_OPTIONS
  });
  const DEFAULT_TELEMETRY_OPTIONS = {
    application: {
      appName: Constants.EMPTY_STRING,
      appVersion: Constants.EMPTY_STRING
    },
    client: new StubPerformanceClient()
  };
  if (userInputAuth?.protocolMode !== ProtocolMode.OIDC && userInputAuth?.OIDCOptions) {
    const logger = new Logger(providedSystemOptions.loggerOptions);
    logger.warning(JSON.stringify(createClientConfigurationError(ClientConfigurationErrorCodes_exports.cannotSetOIDCOptions)));
  }
  if (userInputAuth?.protocolMode && userInputAuth.protocolMode !== ProtocolMode.AAD && providedSystemOptions?.allowPlatformBroker) {
    throw createClientConfigurationError(ClientConfigurationErrorCodes_exports.cannotAllowPlatformBroker);
  }
  const overlayedConfig = {
    auth: __spreadProps(__spreadValues(__spreadValues({}, DEFAULT_AUTH_OPTIONS), userInputAuth), {
      OIDCOptions: __spreadValues(__spreadValues({}, DEFAULT_AUTH_OPTIONS.OIDCOptions), userInputAuth?.OIDCOptions)
    }),
    cache: __spreadValues(__spreadValues({}, DEFAULT_CACHE_OPTIONS), userInputCache),
    system: providedSystemOptions,
    telemetry: __spreadValues(__spreadValues({}, DEFAULT_TELEMETRY_OPTIONS), userInputTelemetry)
  };
  return overlayedConfig;
}

// node_modules/@azure/msal-browser/dist/packageMetadata.mjs
var name2 = "@azure/msal-browser";
var version2 = "4.5.0";

// node_modules/@azure/msal-browser/dist/operatingcontext/BaseOperatingContext.mjs
var BaseOperatingContext = class _BaseOperatingContext {
  static loggerCallback(level, message) {
    switch (level) {
      case LogLevel.Error:
        console.error(message);
        return;
      case LogLevel.Info:
        console.info(message);
        return;
      case LogLevel.Verbose:
        console.debug(message);
        return;
      case LogLevel.Warning:
        console.warn(message);
        return;
      default:
        console.log(message);
        return;
    }
  }
  constructor(config) {
    this.browserEnvironment = typeof window !== "undefined";
    this.config = buildConfiguration(config, this.browserEnvironment);
    let sessionStorage;
    try {
      sessionStorage = window[BrowserCacheLocation.SessionStorage];
    } catch (e) {
    }
    const logLevelKey = sessionStorage?.getItem(LOG_LEVEL_CACHE_KEY);
    const piiLoggingKey = sessionStorage?.getItem(LOG_PII_CACHE_KEY)?.toLowerCase();
    const piiLoggingEnabled = piiLoggingKey === "true" ? true : piiLoggingKey === "false" ? false : void 0;
    const loggerOptions = __spreadValues({}, this.config.system.loggerOptions);
    const logLevel = logLevelKey && Object.keys(LogLevel).includes(logLevelKey) ? LogLevel[logLevelKey] : void 0;
    if (logLevel) {
      loggerOptions.loggerCallback = _BaseOperatingContext.loggerCallback;
      loggerOptions.logLevel = logLevel;
    }
    if (piiLoggingEnabled !== void 0) {
      loggerOptions.piiLoggingEnabled = piiLoggingEnabled;
    }
    this.logger = new Logger(loggerOptions, name2, version2);
    this.available = false;
  }
  /**
   * Return the MSAL config
   * @returns BrowserConfiguration
   */
  getConfig() {
    return this.config;
  }
  /**
   * Returns the MSAL Logger
   * @returns Logger
   */
  getLogger() {
    return this.logger;
  }
  isAvailable() {
    return this.available;
  }
  isBrowserEnvironment() {
    return this.browserEnvironment;
  }
};

// node_modules/@azure/msal-browser/dist/naa/BridgeStatusCode.mjs
var BridgeStatusCode = {
  UserInteractionRequired: "USER_INTERACTION_REQUIRED",
  UserCancel: "USER_CANCEL",
  NoNetwork: "NO_NETWORK",
  TransientError: "TRANSIENT_ERROR",
  PersistentError: "PERSISTENT_ERROR",
  Disabled: "DISABLED",
  AccountUnavailable: "ACCOUNT_UNAVAILABLE",
  NestedAppAuthUnavailable: "NESTED_APP_AUTH_UNAVAILABLE"
  // NAA is unavailable in the current context, can retry with standard browser based auth
};

// node_modules/@azure/msal-browser/dist/naa/BridgeProxy.mjs
var BridgeProxy = class _BridgeProxy {
  /**
   * initializeNestedAppAuthBridge - Initializes the bridge to the host app
   * @returns a promise that resolves to an InitializeBridgeResponse or rejects with an Error
   * @remarks This method will be called by the create factory method
   * @remarks If the bridge is not available, this method will throw an error
   */
  static initializeNestedAppAuthBridge() {
    return __async(this, null, function* () {
      if (window === void 0) {
        throw new Error("window is undefined");
      }
      if (window.nestedAppAuthBridge === void 0) {
        throw new Error("window.nestedAppAuthBridge is undefined");
      }
      try {
        window.nestedAppAuthBridge.addEventListener("message", (response) => {
          const responsePayload = typeof response === "string" ? response : response.data;
          const responseEnvelope = JSON.parse(responsePayload);
          const request = _BridgeProxy.bridgeRequests.find((element) => element.requestId === responseEnvelope.requestId);
          if (request !== void 0) {
            _BridgeProxy.bridgeRequests.splice(_BridgeProxy.bridgeRequests.indexOf(request), 1);
            if (responseEnvelope.success) {
              request.resolve(responseEnvelope);
            } else {
              request.reject(responseEnvelope.error);
            }
          }
        });
        const bridgeResponse = yield new Promise((resolve, reject) => {
          const message = _BridgeProxy.buildRequest("GetInitContext");
          const request = {
            requestId: message.requestId,
            method: message.method,
            resolve,
            reject
          };
          _BridgeProxy.bridgeRequests.push(request);
          window.nestedAppAuthBridge.postMessage(JSON.stringify(message));
        });
        return _BridgeProxy.validateBridgeResultOrThrow(bridgeResponse.initContext);
      } catch (error) {
        window.console.log(error);
        throw error;
      }
    });
  }
  /**
   * getTokenInteractive - Attempts to get a token interactively from the bridge
   * @param request A token request
   * @returns a promise that resolves to an auth result or rejects with a BridgeError
   */
  getTokenInteractive(request) {
    return this.getToken("GetTokenPopup", request);
  }
  /**
   * getTokenSilent Attempts to get a token silently from the bridge
   * @param request A token request
   * @returns a promise that resolves to an auth result or rejects with a BridgeError
   */
  getTokenSilent(request) {
    return this.getToken("GetToken", request);
  }
  getToken(requestType, request) {
    return __async(this, null, function* () {
      const result = yield this.sendRequest(requestType, {
        tokenParams: request
      });
      return {
        token: _BridgeProxy.validateBridgeResultOrThrow(result.token),
        account: _BridgeProxy.validateBridgeResultOrThrow(result.account)
      };
    });
  }
  getHostCapabilities() {
    return this.capabilities ?? null;
  }
  getAccountContext() {
    return this.accountContext ? this.accountContext : null;
  }
  static buildRequest(method, requestParams) {
    return __spreadValues({
      messageType: "NestedAppAuthRequest",
      method,
      requestId: createNewGuid(),
      sendTime: Date.now(),
      clientLibrary: BrowserConstants.MSAL_SKU,
      clientLibraryVersion: version2
    }, requestParams);
  }
  /**
   * A method used to send a request to the bridge
   * @param request A token request
   * @returns a promise that resolves to a response of provided type or rejects with a BridgeError
   */
  sendRequest(method, requestParams) {
    const message = _BridgeProxy.buildRequest(method, requestParams);
    const promise = new Promise((resolve, reject) => {
      const request = {
        requestId: message.requestId,
        method: message.method,
        resolve,
        reject
      };
      _BridgeProxy.bridgeRequests.push(request);
      window.nestedAppAuthBridge.postMessage(JSON.stringify(message));
    });
    return promise;
  }
  static validateBridgeResultOrThrow(input) {
    if (input === void 0) {
      const bridgeError = {
        status: BridgeStatusCode.NestedAppAuthUnavailable
      };
      throw bridgeError;
    }
    return input;
  }
  /**
   * Private constructor for BridgeProxy
   * @param sdkName The name of the SDK being used to make requests on behalf of the app
   * @param sdkVersion The version of the SDK being used to make requests on behalf of the app
   * @param capabilities The capabilities of the bridge / SDK / platform broker
   */
  constructor(sdkName, sdkVersion, accountContext, capabilities) {
    this.sdkName = sdkName;
    this.sdkVersion = sdkVersion;
    this.accountContext = accountContext;
    this.capabilities = capabilities;
  }
  /**
   * Factory method for creating an implementation of IBridgeProxy
   * @returns A promise that resolves to a BridgeProxy implementation
   */
  static create() {
    return __async(this, null, function* () {
      const response = yield _BridgeProxy.initializeNestedAppAuthBridge();
      return new _BridgeProxy(response.sdkName, response.sdkVersion, response.accountContext, response.capabilities);
    });
  }
};
BridgeProxy.bridgeRequests = [];

// node_modules/@azure/msal-browser/dist/operatingcontext/NestedAppOperatingContext.mjs
var NestedAppOperatingContext = class _NestedAppOperatingContext extends BaseOperatingContext {
  constructor() {
    super(...arguments);
    this.bridgeProxy = void 0;
    this.accountContext = null;
  }
  /**
   * Return the module name.  Intended for use with import() to enable dynamic import
   * of the implementation associated with this operating context
   * @returns
   */
  getModuleName() {
    return _NestedAppOperatingContext.MODULE_NAME;
  }
  /**
   * Returns the unique identifier for this operating context
   * @returns string
   */
  getId() {
    return _NestedAppOperatingContext.ID;
  }
  /**
   * Returns the current BridgeProxy
   * @returns IBridgeProxy | undefined
   */
  getBridgeProxy() {
    return this.bridgeProxy;
  }
  /**
   * Checks whether the operating context is available.
   * Confirms that the code is running a browser rather.  This is required.
   * @returns Promise<boolean> indicating whether this operating context is currently available.
   */
  initialize() {
    return __async(this, null, function* () {
      try {
        if (typeof window !== "undefined") {
          if (typeof window.__initializeNestedAppAuth === "function") {
            yield window.__initializeNestedAppAuth();
          }
          const bridgeProxy = yield BridgeProxy.create();
          this.accountContext = bridgeProxy.getAccountContext();
          this.bridgeProxy = bridgeProxy;
          this.available = bridgeProxy !== void 0;
        }
      } catch (ex) {
        this.logger.infoPii(`Could not initialize Nested App Auth bridge (${ex})`);
      }
      this.logger.info(`Nested App Auth Bridge available: ${this.available}`);
      return this.available;
    });
  }
};
NestedAppOperatingContext.MODULE_NAME = "";
NestedAppOperatingContext.ID = "NestedAppOperatingContext";

// node_modules/@azure/msal-browser/dist/operatingcontext/StandardOperatingContext.mjs
var StandardOperatingContext = class _StandardOperatingContext extends BaseOperatingContext {
  /**
   * Return the module name.  Intended for use with import() to enable dynamic import
   * of the implementation associated with this operating context
   * @returns
   */
  getModuleName() {
    return _StandardOperatingContext.MODULE_NAME;
  }
  /**
   * Returns the unique identifier for this operating context
   * @returns string
   */
  getId() {
    return _StandardOperatingContext.ID;
  }
  /**
   * Checks whether the operating context is available.
   * Confirms that the code is running a browser rather.  This is required.
   * @returns Promise<boolean> indicating whether this operating context is currently available.
   */
  initialize() {
    return __async(this, null, function* () {
      this.available = typeof window !== "undefined";
      return this.available;
    });
  }
};
StandardOperatingContext.MODULE_NAME = "";
StandardOperatingContext.ID = "StandardOperatingContext";

// node_modules/@azure/msal-browser/dist/cache/DatabaseStorage.mjs
var DatabaseStorage = class {
  constructor() {
    this.dbName = DB_NAME;
    this.version = DB_VERSION;
    this.tableName = DB_TABLE_NAME;
    this.dbOpen = false;
  }
  /**
   * Opens IndexedDB instance.
   */
  open() {
    return __async(this, null, function* () {
      return new Promise((resolve, reject) => {
        const openDB = window.indexedDB.open(this.dbName, this.version);
        openDB.addEventListener("upgradeneeded", (e) => {
          const event = e;
          event.target.result.createObjectStore(this.tableName);
        });
        openDB.addEventListener("success", (e) => {
          const event = e;
          this.db = event.target.result;
          this.dbOpen = true;
          resolve();
        });
        openDB.addEventListener("error", () => reject(createBrowserAuthError(databaseUnavailable)));
      });
    });
  }
  /**
   * Closes the connection to IndexedDB database when all pending transactions
   * complete.
   */
  closeConnection() {
    const db = this.db;
    if (db && this.dbOpen) {
      db.close();
      this.dbOpen = false;
    }
  }
  /**
   * Opens database if it's not already open
   */
  validateDbIsOpen() {
    return __async(this, null, function* () {
      if (!this.dbOpen) {
        return this.open();
      }
    });
  }
  /**
   * Retrieves item from IndexedDB instance.
   * @param key
   */
  getItem(key) {
    return __async(this, null, function* () {
      yield this.validateDbIsOpen();
      return new Promise((resolve, reject) => {
        if (!this.db) {
          return reject(createBrowserAuthError(databaseNotOpen));
        }
        const transaction = this.db.transaction([this.tableName], "readonly");
        const objectStore = transaction.objectStore(this.tableName);
        const dbGet = objectStore.get(key);
        dbGet.addEventListener("success", (e) => {
          const event = e;
          this.closeConnection();
          resolve(event.target.result);
        });
        dbGet.addEventListener("error", (e) => {
          this.closeConnection();
          reject(e);
        });
      });
    });
  }
  /**
   * Adds item to IndexedDB under given key
   * @param key
   * @param payload
   */
  setItem(key, payload) {
    return __async(this, null, function* () {
      yield this.validateDbIsOpen();
      return new Promise((resolve, reject) => {
        if (!this.db) {
          return reject(createBrowserAuthError(databaseNotOpen));
        }
        const transaction = this.db.transaction([this.tableName], "readwrite");
        const objectStore = transaction.objectStore(this.tableName);
        const dbPut = objectStore.put(payload, key);
        dbPut.addEventListener("success", () => {
          this.closeConnection();
          resolve();
        });
        dbPut.addEventListener("error", (e) => {
          this.closeConnection();
          reject(e);
        });
      });
    });
  }
  /**
   * Removes item from IndexedDB under given key
   * @param key
   */
  removeItem(key) {
    return __async(this, null, function* () {
      yield this.validateDbIsOpen();
      return new Promise((resolve, reject) => {
        if (!this.db) {
          return reject(createBrowserAuthError(databaseNotOpen));
        }
        const transaction = this.db.transaction([this.tableName], "readwrite");
        const objectStore = transaction.objectStore(this.tableName);
        const dbDelete = objectStore.delete(key);
        dbDelete.addEventListener("success", () => {
          this.closeConnection();
          resolve();
        });
        dbDelete.addEventListener("error", (e) => {
          this.closeConnection();
          reject(e);
        });
      });
    });
  }
  /**
   * Get all the keys from the storage object as an iterable array of strings.
   */
  getKeys() {
    return __async(this, null, function* () {
      yield this.validateDbIsOpen();
      return new Promise((resolve, reject) => {
        if (!this.db) {
          return reject(createBrowserAuthError(databaseNotOpen));
        }
        const transaction = this.db.transaction([this.tableName], "readonly");
        const objectStore = transaction.objectStore(this.tableName);
        const dbGetKeys = objectStore.getAllKeys();
        dbGetKeys.addEventListener("success", (e) => {
          const event = e;
          this.closeConnection();
          resolve(event.target.result);
        });
        dbGetKeys.addEventListener("error", (e) => {
          this.closeConnection();
          reject(e);
        });
      });
    });
  }
  /**
   *
   * Checks whether there is an object under the search key in the object store
   */
  containsKey(key) {
    return __async(this, null, function* () {
      yield this.validateDbIsOpen();
      return new Promise((resolve, reject) => {
        if (!this.db) {
          return reject(createBrowserAuthError(databaseNotOpen));
        }
        const transaction = this.db.transaction([this.tableName], "readonly");
        const objectStore = transaction.objectStore(this.tableName);
        const dbContainsKey = objectStore.count(key);
        dbContainsKey.addEventListener("success", (e) => {
          const event = e;
          this.closeConnection();
          resolve(event.target.result === 1);
        });
        dbContainsKey.addEventListener("error", (e) => {
          this.closeConnection();
          reject(e);
        });
      });
    });
  }
  /**
   * Deletes the MSAL database. The database is deleted rather than cleared to make it possible
   * for client applications to downgrade to a previous MSAL version without worrying about forward compatibility issues
   * with IndexedDB database versions.
   */
  deleteDatabase() {
    return __async(this, null, function* () {
      if (this.db && this.dbOpen) {
        this.closeConnection();
      }
      return new Promise((resolve, reject) => {
        const deleteDbRequest = window.indexedDB.deleteDatabase(DB_NAME);
        const id = setTimeout(() => reject(false), 200);
        deleteDbRequest.addEventListener("success", () => {
          clearTimeout(id);
          return resolve(true);
        });
        deleteDbRequest.addEventListener("blocked", () => {
          clearTimeout(id);
          return resolve(true);
        });
        deleteDbRequest.addEventListener("error", () => {
          clearTimeout(id);
          return reject(false);
        });
      });
    });
  }
};

// node_modules/@azure/msal-browser/dist/cache/MemoryStorage.mjs
var MemoryStorage = class {
  constructor() {
    this.cache = /* @__PURE__ */ new Map();
  }
  initialize() {
    return __async(this, null, function* () {
    });
  }
  getItem(key) {
    return this.cache.get(key) || null;
  }
  getUserData(key) {
    return this.getItem(key);
  }
  setItem(key, value) {
    this.cache.set(key, value);
  }
  setUserData(key, value) {
    return __async(this, null, function* () {
      this.setItem(key, value);
    });
  }
  removeItem(key) {
    this.cache.delete(key);
  }
  getKeys() {
    const cacheKeys = [];
    this.cache.forEach((value, key) => {
      cacheKeys.push(key);
    });
    return cacheKeys;
  }
  containsKey(key) {
    return this.cache.has(key);
  }
  clear() {
    this.cache.clear();
  }
};

// node_modules/@azure/msal-browser/dist/cache/AsyncMemoryStorage.mjs
var AsyncMemoryStorage = class {
  constructor(logger) {
    this.inMemoryCache = new MemoryStorage();
    this.indexedDBCache = new DatabaseStorage();
    this.logger = logger;
  }
  handleDatabaseAccessError(error) {
    if (error instanceof BrowserAuthError && error.errorCode === databaseUnavailable) {
      this.logger.error("Could not access persistent storage. This may be caused by browser privacy features which block persistent storage in third-party contexts.");
    } else {
      throw error;
    }
  }
  /**
   * Get the item matching the given key. Tries in-memory cache first, then in the asynchronous
   * storage object if item isn't found in-memory.
   * @param key
   */
  getItem(key) {
    return __async(this, null, function* () {
      const item = this.inMemoryCache.getItem(key);
      if (!item) {
        try {
          this.logger.verbose("Queried item not found in in-memory cache, now querying persistent storage.");
          return yield this.indexedDBCache.getItem(key);
        } catch (e) {
          this.handleDatabaseAccessError(e);
        }
      }
      return item;
    });
  }
  /**
   * Sets the item in the in-memory cache and then tries to set it in the asynchronous
   * storage object with the given key.
   * @param key
   * @param value
   */
  setItem(key, value) {
    return __async(this, null, function* () {
      this.inMemoryCache.setItem(key, value);
      try {
        yield this.indexedDBCache.setItem(key, value);
      } catch (e) {
        this.handleDatabaseAccessError(e);
      }
    });
  }
  /**
   * Removes the item matching the key from the in-memory cache, then tries to remove it from the asynchronous storage object.
   * @param key
   */
  removeItem(key) {
    return __async(this, null, function* () {
      this.inMemoryCache.removeItem(key);
      try {
        yield this.indexedDBCache.removeItem(key);
      } catch (e) {
        this.handleDatabaseAccessError(e);
      }
    });
  }
  /**
   * Get all the keys from the in-memory cache as an iterable array of strings. If no keys are found, query the keys in the
   * asynchronous storage object.
   */
  getKeys() {
    return __async(this, null, function* () {
      const cacheKeys = this.inMemoryCache.getKeys();
      if (cacheKeys.length === 0) {
        try {
          this.logger.verbose("In-memory cache is empty, now querying persistent storage.");
          return yield this.indexedDBCache.getKeys();
        } catch (e) {
          this.handleDatabaseAccessError(e);
        }
      }
      return cacheKeys;
    });
  }
  /**
   * Returns true or false if the given key is present in the cache.
   * @param key
   */
  containsKey(key) {
    return __async(this, null, function* () {
      const containsKey = this.inMemoryCache.containsKey(key);
      if (!containsKey) {
        try {
          this.logger.verbose("Key not found in in-memory cache, now querying persistent storage.");
          return yield this.indexedDBCache.containsKey(key);
        } catch (e) {
          this.handleDatabaseAccessError(e);
        }
      }
      return containsKey;
    });
  }
  /**
   * Clears in-memory Map
   */
  clearInMemory() {
    this.logger.verbose(`Deleting in-memory keystore`);
    this.inMemoryCache.clear();
    this.logger.verbose(`In-memory keystore deleted`);
  }
  /**
   * Tries to delete the IndexedDB database
   * @returns
   */
  clearPersistent() {
    return __async(this, null, function* () {
      try {
        this.logger.verbose("Deleting persistent keystore");
        const dbDeleted = yield this.indexedDBCache.deleteDatabase();
        if (dbDeleted) {
          this.logger.verbose("Persistent keystore deleted");
        }
        return dbDeleted;
      } catch (e) {
        this.handleDatabaseAccessError(e);
        return false;
      }
    });
  }
};

// node_modules/@azure/msal-browser/dist/crypto/CryptoOps.mjs
var CryptoOps = class _CryptoOps {
  constructor(logger, performanceClient, skipValidateSubtleCrypto) {
    this.logger = logger;
    validateCryptoAvailable(skipValidateSubtleCrypto ?? false);
    this.cache = new AsyncMemoryStorage(this.logger);
    this.performanceClient = performanceClient;
  }
  /**
   * Creates a new random GUID - used to populate state and nonce.
   * @returns string (GUID)
   */
  createNewGuid() {
    return createNewGuid();
  }
  /**
   * Encodes input string to base64.
   * @param input
   */
  base64Encode(input) {
    return base64Encode(input);
  }
  /**
   * Decodes input string from base64.
   * @param input
   */
  base64Decode(input) {
    return base64Decode(input);
  }
  /**
   * Encodes input string to base64 URL safe string.
   * @param input
   */
  base64UrlEncode(input) {
    return urlEncode(input);
  }
  /**
   * Stringifies and base64Url encodes input public key
   * @param inputKid
   * @returns Base64Url encoded public key
   */
  encodeKid(inputKid) {
    return this.base64UrlEncode(JSON.stringify({
      kid: inputKid
    }));
  }
  /**
   * Generates a keypair, stores it and returns a thumbprint
   * @param request
   */
  getPublicKeyThumbprint(request) {
    return __async(this, null, function* () {
      const publicKeyThumbMeasurement = this.performanceClient?.startMeasurement(PerformanceEvents.CryptoOptsGetPublicKeyThumbprint, request.correlationId);
      const keyPair = yield generateKeyPair(_CryptoOps.EXTRACTABLE, _CryptoOps.POP_KEY_USAGES);
      const publicKeyJwk = yield exportJwk(keyPair.publicKey);
      const pubKeyThumprintObj = {
        e: publicKeyJwk.e,
        kty: publicKeyJwk.kty,
        n: publicKeyJwk.n
      };
      const publicJwkString = getSortedObjectString(pubKeyThumprintObj);
      const publicJwkHash = yield this.hashString(publicJwkString);
      const privateKeyJwk = yield exportJwk(keyPair.privateKey);
      const unextractablePrivateKey = yield importJwk(privateKeyJwk, false, ["sign"]);
      yield this.cache.setItem(publicJwkHash, {
        privateKey: unextractablePrivateKey,
        publicKey: keyPair.publicKey,
        requestMethod: request.resourceRequestMethod,
        requestUri: request.resourceRequestUri
      });
      if (publicKeyThumbMeasurement) {
        publicKeyThumbMeasurement.end({
          success: true
        });
      }
      return publicJwkHash;
    });
  }
  /**
   * Removes cryptographic keypair from key store matching the keyId passed in
   * @param kid
   */
  removeTokenBindingKey(kid) {
    return __async(this, null, function* () {
      yield this.cache.removeItem(kid);
      const keyFound = yield this.cache.containsKey(kid);
      return !keyFound;
    });
  }
  /**
   * Removes all cryptographic keys from IndexedDB storage
   */
  clearKeystore() {
    return __async(this, null, function* () {
      this.cache.clearInMemory();
      try {
        yield this.cache.clearPersistent();
        return true;
      } catch (e) {
        if (e instanceof Error) {
          this.logger.error(`Clearing keystore failed with error: ${e.message}`);
        } else {
          this.logger.error("Clearing keystore failed with unknown error");
        }
        return false;
      }
    });
  }
  /**
   * Signs the given object as a jwt payload with private key retrieved by given kid.
   * @param payload
   * @param kid
   */
  signJwt(payload, kid, shrOptions, correlationId) {
    return __async(this, null, function* () {
      const signJwtMeasurement = this.performanceClient?.startMeasurement(PerformanceEvents.CryptoOptsSignJwt, correlationId);
      const cachedKeyPair = yield this.cache.getItem(kid);
      if (!cachedKeyPair) {
        throw createBrowserAuthError(cryptoKeyNotFound);
      }
      const publicKeyJwk = yield exportJwk(cachedKeyPair.publicKey);
      const publicKeyJwkString = getSortedObjectString(publicKeyJwk);
      const encodedKeyIdThumbprint = urlEncode(JSON.stringify({
        kid
      }));
      const shrHeader = JoseHeader.getShrHeaderString(__spreadProps(__spreadValues({}, shrOptions?.header), {
        alg: publicKeyJwk.alg,
        kid: encodedKeyIdThumbprint
      }));
      const encodedShrHeader = urlEncode(shrHeader);
      payload.cnf = {
        jwk: JSON.parse(publicKeyJwkString)
      };
      const encodedPayload = urlEncode(JSON.stringify(payload));
      const tokenString = `${encodedShrHeader}.${encodedPayload}`;
      const encoder = new TextEncoder();
      const tokenBuffer = encoder.encode(tokenString);
      const signatureBuffer = yield sign(cachedKeyPair.privateKey, tokenBuffer);
      const encodedSignature = urlEncodeArr(new Uint8Array(signatureBuffer));
      const signedJwt = `${tokenString}.${encodedSignature}`;
      if (signJwtMeasurement) {
        signJwtMeasurement.end({
          success: true
        });
      }
      return signedJwt;
    });
  }
  /**
   * Returns the SHA-256 hash of an input string
   * @param plainText
   */
  hashString(plainText) {
    return __async(this, null, function* () {
      return hashString(plainText);
    });
  }
};
CryptoOps.POP_KEY_USAGES = ["sign", "verify"];
CryptoOps.EXTRACTABLE = true;
function getSortedObjectString(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

// node_modules/@azure/msal-browser/dist/cache/CookieStorage.mjs
var COOKIE_LIFE_MULTIPLIER = 24 * 60 * 60 * 1e3;

// node_modules/@azure/msal-browser/dist/event/EventType.mjs
var EventType = {
  INITIALIZE_START: "msal:initializeStart",
  INITIALIZE_END: "msal:initializeEnd",
  ACCOUNT_ADDED: "msal:accountAdded",
  ACCOUNT_REMOVED: "msal:accountRemoved",
  ACTIVE_ACCOUNT_CHANGED: "msal:activeAccountChanged",
  LOGIN_START: "msal:loginStart",
  LOGIN_SUCCESS: "msal:loginSuccess",
  LOGIN_FAILURE: "msal:loginFailure",
  ACQUIRE_TOKEN_START: "msal:acquireTokenStart",
  ACQUIRE_TOKEN_SUCCESS: "msal:acquireTokenSuccess",
  ACQUIRE_TOKEN_FAILURE: "msal:acquireTokenFailure",
  ACQUIRE_TOKEN_NETWORK_START: "msal:acquireTokenFromNetworkStart",
  SSO_SILENT_START: "msal:ssoSilentStart",
  SSO_SILENT_SUCCESS: "msal:ssoSilentSuccess",
  SSO_SILENT_FAILURE: "msal:ssoSilentFailure",
  ACQUIRE_TOKEN_BY_CODE_START: "msal:acquireTokenByCodeStart",
  ACQUIRE_TOKEN_BY_CODE_SUCCESS: "msal:acquireTokenByCodeSuccess",
  ACQUIRE_TOKEN_BY_CODE_FAILURE: "msal:acquireTokenByCodeFailure",
  HANDLE_REDIRECT_START: "msal:handleRedirectStart",
  HANDLE_REDIRECT_END: "msal:handleRedirectEnd",
  POPUP_OPENED: "msal:popupOpened",
  LOGOUT_START: "msal:logoutStart",
  LOGOUT_SUCCESS: "msal:logoutSuccess",
  LOGOUT_FAILURE: "msal:logoutFailure",
  LOGOUT_END: "msal:logoutEnd",
  RESTORE_FROM_BFCACHE: "msal:restoreFromBFCache"
};

// node_modules/@azure/msal-browser/dist/error/NativeAuthErrorCodes.mjs
var userSwitch = "user_switch";

// node_modules/@azure/msal-browser/dist/error/NativeAuthError.mjs
var NativeAuthErrorMessages = {
  [userSwitch]: "User attempted to switch accounts in the native broker, which is not allowed. All new accounts must sign-in through the standard web flow first, please try again."
};

// node_modules/@azure/msal-browser/dist/operatingcontext/UnknownOperatingContext.mjs
var UnknownOperatingContext = class _UnknownOperatingContext extends BaseOperatingContext {
  /**
   * Returns the unique identifier for this operating context
   * @returns string
   */
  getId() {
    return _UnknownOperatingContext.ID;
  }
  /**
   * Return the module name.  Intended for use with import() to enable dynamic import
   * of the implementation associated with this operating context
   * @returns
   */
  getModuleName() {
    return _UnknownOperatingContext.MODULE_NAME;
  }
  /**
   * Checks whether the operating context is available.
   * Confirms that the code is running a browser rather.  This is required.
   * @returns Promise<boolean> indicating whether this operating context is currently available.
   */
  initialize() {
    return __async(this, null, function* () {
      return true;
    });
  }
};
UnknownOperatingContext.MODULE_NAME = "";
UnknownOperatingContext.ID = "UnknownOperatingContext";

// node_modules/@azure/msal-browser/dist/event/EventMessage.mjs
var EventMessageUtils = class {
  /**
   * Gets interaction status from event message
   * @param message
   * @param currentStatus
   */
  static getInteractionStatusFromEvent(message, currentStatus) {
    switch (message.eventType) {
      case EventType.LOGIN_START:
        return InteractionStatus.Login;
      case EventType.SSO_SILENT_START:
        return InteractionStatus.SsoSilent;
      case EventType.ACQUIRE_TOKEN_START:
        if (message.interactionType === InteractionType.Redirect || message.interactionType === InteractionType.Popup) {
          return InteractionStatus.AcquireToken;
        }
        break;
      case EventType.HANDLE_REDIRECT_START:
        return InteractionStatus.HandleRedirect;
      case EventType.LOGOUT_START:
        return InteractionStatus.Logout;
      case EventType.SSO_SILENT_SUCCESS:
      case EventType.SSO_SILENT_FAILURE:
        if (currentStatus && currentStatus !== InteractionStatus.SsoSilent) {
          break;
        }
        return InteractionStatus.None;
      case EventType.LOGOUT_END:
        if (currentStatus && currentStatus !== InteractionStatus.Logout) {
          break;
        }
        return InteractionStatus.None;
      case EventType.HANDLE_REDIRECT_END:
        if (currentStatus && currentStatus !== InteractionStatus.HandleRedirect) {
          break;
        }
        return InteractionStatus.None;
      case EventType.LOGIN_SUCCESS:
      case EventType.LOGIN_FAILURE:
      case EventType.ACQUIRE_TOKEN_SUCCESS:
      case EventType.ACQUIRE_TOKEN_FAILURE:
      case EventType.RESTORE_FROM_BFCACHE:
        if (message.interactionType === InteractionType.Redirect || message.interactionType === InteractionType.Popup) {
          if (currentStatus && currentStatus !== InteractionStatus.Login && currentStatus !== InteractionStatus.AcquireToken) {
            break;
          }
          return InteractionStatus.None;
        }
        break;
    }
    return null;
  }
};

// node_modules/@azure/msal-angular/fesm2015/azure-msal-angular.mjs
var import_rxjs = __toESM(require_cjs(), 1);
var import_operators = __toESM(require_operators(), 1);

// node_modules/tslib/tslib.es6.mjs
function __awaiter(thisArg, _arguments, P, generator) {
  function adopt(value) {
    return value instanceof P ? value : new P(function(resolve) {
      resolve(value);
    });
  }
  return new (P || (P = Promise))(function(resolve, reject) {
    function fulfilled(value) {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    }
    function rejected(value) {
      try {
        step(generator["throw"](value));
      } catch (e) {
        reject(e);
      }
    }
    function step(result) {
      result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
    }
    step((generator = generator.apply(thisArg, _arguments || [])).next());
  });
}

// node_modules/@azure/msal-angular/fesm2015/azure-msal-angular.mjs
var name3 = "@azure/msal-angular";
var version3 = "4.0.5";
var MSAL_INSTANCE = new InjectionToken("MSAL_INSTANCE");
var MSAL_GUARD_CONFIG = new InjectionToken("MSAL_GUARD_CONFIG");
var MSAL_INTERCEPTOR_CONFIG = new InjectionToken("MSAL_INTERCEPTOR_CONFIG");
var MSAL_BROADCAST_CONFIG = new InjectionToken("MSAL_BROADCAST_CONFIG");
var MsalService = class {
  constructor(instance, location) {
    this.instance = instance;
    this.location = location;
    const hash = this.location.path(true).split("#").pop();
    if (hash) {
      this.redirectHash = `#${hash}`;
    }
    this.instance.initializeWrapperLibrary(WrapperSKU.Angular, version3);
  }
  initialize() {
    return (0, import_rxjs.from)(this.instance.initialize());
  }
  acquireTokenPopup(request) {
    return (0, import_rxjs.from)(this.instance.acquireTokenPopup(request));
  }
  acquireTokenRedirect(request) {
    return (0, import_rxjs.from)(this.instance.acquireTokenRedirect(request));
  }
  acquireTokenSilent(silentRequest) {
    return (0, import_rxjs.from)(this.instance.acquireTokenSilent(silentRequest));
  }
  handleRedirectObservable(hash) {
    return (0, import_rxjs.from)(this.instance.initialize().then(() => this.instance.handleRedirectPromise(hash || this.redirectHash)));
  }
  loginPopup(request) {
    return (0, import_rxjs.from)(this.instance.loginPopup(request));
  }
  loginRedirect(request) {
    return (0, import_rxjs.from)(this.instance.loginRedirect(request));
  }
  logout(logoutRequest) {
    return (0, import_rxjs.from)(this.instance.logout(logoutRequest));
  }
  logoutRedirect(logoutRequest) {
    return (0, import_rxjs.from)(this.instance.logoutRedirect(logoutRequest));
  }
  logoutPopup(logoutRequest) {
    return (0, import_rxjs.from)(this.instance.logoutPopup(logoutRequest));
  }
  ssoSilent(request) {
    return (0, import_rxjs.from)(this.instance.ssoSilent(request));
  }
  /**
   * Gets logger for msal-angular.
   * If no logger set, returns logger instance created with same options as msal-browser
   */
  getLogger() {
    if (!this.logger) {
      this.logger = this.instance.getLogger().clone(name3, version3);
    }
    return this.logger;
  }
  // Create a logger instance for msal-angular with the same options as msal-browser
  setLogger(logger) {
    this.logger = logger.clone(name3, version3);
    this.instance.setLogger(logger);
  }
};
MsalService.ɵfac = function MsalService_Factory(__ngFactoryType__) {
  return new (__ngFactoryType__ || MsalService)(ɵɵinject(MSAL_INSTANCE), ɵɵinject(Location));
};
MsalService.ɵprov = ɵɵdefineInjectable({
  token: MsalService,
  factory: MsalService.ɵfac
});
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(MsalService, [{
    type: Injectable
  }], function() {
    return [{
      type: void 0,
      decorators: [{
        type: Inject,
        args: [MSAL_INSTANCE]
      }]
    }, {
      type: Location
    }];
  }, null);
})();
var MsalBroadcastService = class {
  constructor(msalInstance, authService, msalBroadcastConfig) {
    this.msalInstance = msalInstance;
    this.authService = authService;
    this.msalBroadcastConfig = msalBroadcastConfig;
    if (this.msalBroadcastConfig && this.msalBroadcastConfig.eventsToReplay > 0) {
      this.authService.getLogger().verbose(`BroadcastService - eventsToReplay set on BroadcastConfig, replaying the last ${this.msalBroadcastConfig.eventsToReplay} events`);
      this._msalSubject = new import_rxjs.ReplaySubject(this.msalBroadcastConfig.eventsToReplay);
    } else {
      this._msalSubject = new import_rxjs.Subject();
    }
    this.msalSubject$ = this._msalSubject.asObservable();
    this._inProgress = new import_rxjs.BehaviorSubject(InteractionStatus.Startup);
    this.inProgress$ = this._inProgress.asObservable();
    this.msalInstance.addEventCallback((message) => {
      this._msalSubject.next(message);
      const status = EventMessageUtils.getInteractionStatusFromEvent(message, this._inProgress.value);
      if (status !== null) {
        this.authService.getLogger().verbose(`BroadcastService - ${message.eventType} results in setting inProgress from ${this._inProgress.value} to ${status}`);
        this._inProgress.next(status);
      }
    });
  }
};
MsalBroadcastService.ɵfac = function MsalBroadcastService_Factory(__ngFactoryType__) {
  return new (__ngFactoryType__ || MsalBroadcastService)(ɵɵinject(MSAL_INSTANCE), ɵɵinject(MsalService), ɵɵinject(MSAL_BROADCAST_CONFIG, 8));
};
MsalBroadcastService.ɵprov = ɵɵdefineInjectable({
  token: MsalBroadcastService,
  factory: MsalBroadcastService.ɵfac
});
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(MsalBroadcastService, [{
    type: Injectable
  }], function() {
    return [{
      type: void 0,
      decorators: [{
        type: Inject,
        args: [MSAL_INSTANCE]
      }]
    }, {
      type: MsalService
    }, {
      type: void 0,
      decorators: [{
        type: Optional
      }, {
        type: Inject,
        args: [MSAL_BROADCAST_CONFIG]
      }]
    }];
  }, null);
})();
var MsalGuard = class {
  constructor(msalGuardConfig, msalBroadcastService, authService, location, router) {
    this.msalGuardConfig = msalGuardConfig;
    this.msalBroadcastService = msalBroadcastService;
    this.authService = authService;
    this.location = location;
    this.router = router;
    this.msalBroadcastService.inProgress$.subscribe();
  }
  /**
   * Parses url string to UrlTree
   * @param url
   */
  parseUrl(url) {
    return this.router.parseUrl(url);
  }
  /**
   * Builds the absolute url for the destination page
   * @param path Relative path of requested page
   * @returns Full destination url
   */
  getDestinationUrl(path) {
    this.authService.getLogger().verbose("Guard - getting destination url");
    const baseElements = document.getElementsByTagName("base");
    const baseUrl = this.location.normalize(baseElements.length ? baseElements[0].href : window.location.origin);
    const pathUrl = this.location.prepareExternalUrl(path);
    if (pathUrl.startsWith("#")) {
      this.authService.getLogger().verbose("Guard - destination by hash routing");
      return `${baseUrl}/${pathUrl}`;
    }
    return `${baseUrl}${path}`;
  }
  /**
   * Interactively prompt the user to login
   * @param url Path of the requested page
   */
  loginInteractively(state) {
    const authRequest = typeof this.msalGuardConfig.authRequest === "function" ? this.msalGuardConfig.authRequest(this.authService, state) : Object.assign({}, this.msalGuardConfig.authRequest);
    if (this.msalGuardConfig.interactionType === InteractionType.Popup) {
      this.authService.getLogger().verbose("Guard - logging in by popup");
      return this.authService.loginPopup(authRequest).pipe((0, import_operators.map)((response) => {
        this.authService.getLogger().verbose("Guard - login by popup successful, can activate, setting active account");
        this.authService.instance.setActiveAccount(response.account);
        return true;
      }));
    }
    this.authService.getLogger().verbose("Guard - logging in by redirect");
    const redirectStartPage = this.getDestinationUrl(state.url);
    return this.authService.loginRedirect(Object.assign({
      redirectStartPage
    }, authRequest)).pipe((0, import_operators.map)(() => false));
  }
  /**
   * Helper which checks for the correct interaction type, prevents page with Guard to be set as redirect, and calls handleRedirectObservable
   * @param state
   */
  activateHelper(state) {
    if (this.msalGuardConfig.interactionType !== InteractionType.Popup && this.msalGuardConfig.interactionType !== InteractionType.Redirect) {
      throw new BrowserConfigurationAuthError("invalid_interaction_type", "Invalid interaction type provided to MSAL Guard. InteractionType.Popup or InteractionType.Redirect must be provided in the MsalGuardConfiguration");
    }
    this.authService.getLogger().verbose("MSAL Guard activated");
    if (typeof window !== "undefined") {
      if (UrlString.hashContainsKnownProperties(window.location.hash) && BrowserUtils_exports.isInIframe() && !this.authService.instance.getConfiguration().system.allowRedirectInIframe) {
        this.authService.getLogger().warning("Guard - redirectUri set to page with MSAL Guard. It is recommended to not set redirectUri to a page that requires authentication.");
        return (0, import_rxjs.of)(false);
      }
    } else {
      this.authService.getLogger().info("Guard - window is undefined, MSAL does not support server-side token acquisition");
      return (0, import_rxjs.of)(true);
    }
    if (this.msalGuardConfig.loginFailedRoute) {
      this.loginFailedRoute = this.parseUrl(this.msalGuardConfig.loginFailedRoute);
    }
    const currentPath = this.location.path(true);
    return this.authService.initialize().pipe((0, import_operators.concatMap)(() => {
      return this.authService.handleRedirectObservable();
    }), (0, import_operators.concatMap)(() => {
      if (!this.authService.instance.getAllAccounts().length) {
        if (state) {
          this.authService.getLogger().verbose("Guard - no accounts retrieved, log in required to activate");
          return this.loginInteractively(state);
        }
        this.authService.getLogger().verbose("Guard - no accounts retrieved, no state, cannot load");
        return (0, import_rxjs.of)(false);
      }
      this.authService.getLogger().verbose("Guard - at least 1 account exists, can activate or load");
      if (state) {
        const urlContainsCode = this.includesCode(state.url);
        const fragmentContainsCode = !!state.root && !!state.root.fragment && this.includesCode(`#${state.root.fragment}`);
        const hashRouting = this.location.prepareExternalUrl(state.url).indexOf("#") === 0;
        if (urlContainsCode && (fragmentContainsCode || hashRouting)) {
          this.authService.getLogger().info("Guard - Hash contains known code response, stopping navigation.");
          if (currentPath.indexOf("#") > -1) {
            return (0, import_rxjs.of)(this.parseUrl(this.location.path()));
          }
          return (0, import_rxjs.of)(this.parseUrl(""));
        }
      }
      return (0, import_rxjs.of)(true);
    }), (0, import_operators.catchError)((error) => {
      this.authService.getLogger().error("Guard - error while logging in, unable to activate");
      this.authService.getLogger().errorPii(`Guard - error: ${error.message}`);
      if (this.loginFailedRoute && state) {
        this.authService.getLogger().verbose("Guard - loginFailedRoute set, redirecting");
        return (0, import_rxjs.of)(this.loginFailedRoute);
      }
      return (0, import_rxjs.of)(false);
    }));
  }
  includesCode(path) {
    return path.lastIndexOf("/code") > -1 && path.lastIndexOf("/code") === path.length - "/code".length || // path.endsWith("/code")
    path.indexOf("#code=") > -1 || path.indexOf("&code=") > -1;
  }
  canActivate(route, state) {
    this.authService.getLogger().verbose("Guard - canActivate");
    return this.activateHelper(state);
  }
  canActivateChild(route, state) {
    this.authService.getLogger().verbose("Guard - canActivateChild");
    return this.activateHelper(state);
  }
  canMatch() {
    this.authService.getLogger().verbose("Guard - canLoad");
    return this.activateHelper();
  }
};
MsalGuard.ɵfac = function MsalGuard_Factory(__ngFactoryType__) {
  return new (__ngFactoryType__ || MsalGuard)(ɵɵinject(MSAL_GUARD_CONFIG), ɵɵinject(MsalBroadcastService), ɵɵinject(MsalService), ɵɵinject(Location), ɵɵinject(Router));
};
MsalGuard.ɵprov = ɵɵdefineInjectable({
  token: MsalGuard,
  factory: MsalGuard.ɵfac
});
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(MsalGuard, [{
    type: Injectable
  }], function() {
    return [{
      type: void 0,
      decorators: [{
        type: Inject,
        args: [MSAL_GUARD_CONFIG]
      }]
    }, {
      type: MsalBroadcastService
    }, {
      type: MsalService
    }, {
      type: Location
    }, {
      type: Router
    }];
  }, null);
})();
var MsalInterceptor = class {
  constructor(msalInterceptorConfig, authService, location, msalBroadcastService, document2) {
    this.msalInterceptorConfig = msalInterceptorConfig;
    this.authService = authService;
    this.location = location;
    this.msalBroadcastService = msalBroadcastService;
    this._document = document2;
  }
  intercept(req, next) {
    if (this.msalInterceptorConfig.interactionType !== InteractionType.Popup && this.msalInterceptorConfig.interactionType !== InteractionType.Redirect) {
      throw new BrowserConfigurationAuthError("invalid_interaction_type", "Invalid interaction type provided to MSAL Interceptor. InteractionType.Popup, InteractionType.Redirect must be provided in the msalInterceptorConfiguration");
    }
    this.authService.getLogger().verbose("MSAL Interceptor activated");
    const scopes = this.getScopesForEndpoint(req.url, req.method);
    if (!scopes || scopes.length === 0) {
      this.authService.getLogger().verbose("Interceptor - no scopes for endpoint");
      return next.handle(req);
    }
    let account;
    if (!!this.authService.instance.getActiveAccount()) {
      this.authService.getLogger().verbose("Interceptor - active account selected");
      account = this.authService.instance.getActiveAccount();
    } else {
      this.authService.getLogger().verbose("Interceptor - no active account, fallback to first account");
      account = this.authService.instance.getAllAccounts()[0];
    }
    const authRequest = typeof this.msalInterceptorConfig.authRequest === "function" ? this.msalInterceptorConfig.authRequest(this.authService, req, {
      account
    }) : Object.assign(Object.assign({}, this.msalInterceptorConfig.authRequest), {
      account
    });
    this.authService.getLogger().info(`Interceptor - ${scopes.length} scopes found for endpoint`);
    this.authService.getLogger().infoPii(`Interceptor - [${scopes}] scopes found for ${req.url}`);
    return this.acquireToken(authRequest, scopes, account).pipe((0, import_operators.switchMap)((result) => {
      this.authService.getLogger().verbose("Interceptor - setting authorization headers");
      const headers = req.headers.set("Authorization", `Bearer ${result.accessToken}`);
      const requestClone = req.clone({
        headers
      });
      return next.handle(requestClone);
    }));
  }
  /**
   * Try to acquire token silently. Invoke interaction if acquireTokenSilent rejected with error or resolved with null access token
   * @param authRequest Request
   * @param scopes Array of scopes for the request
   * @param account Account
   * @returns Authentication result
   */
  acquireToken(authRequest, scopes, account) {
    return this.authService.acquireTokenSilent(Object.assign(Object.assign({}, authRequest), {
      scopes,
      account
    })).pipe((0, import_operators.catchError)(() => {
      this.authService.getLogger().error("Interceptor - acquireTokenSilent rejected with error. Invoking interaction to resolve.");
      return this.msalBroadcastService.inProgress$.pipe((0, import_operators.take)(1), (0, import_operators.switchMap)((status) => {
        if (status === InteractionStatus.None) {
          return this.acquireTokenInteractively(authRequest, scopes);
        }
        return this.msalBroadcastService.inProgress$.pipe((0, import_operators.filter)((status2) => status2 === InteractionStatus.None), (0, import_operators.take)(1), (0, import_operators.switchMap)(() => this.acquireToken(authRequest, scopes, account)));
      }));
    }), (0, import_operators.switchMap)((result) => {
      if (!result.accessToken) {
        this.authService.getLogger().error("Interceptor - acquireTokenSilent resolved with null access token. Known issue with B2C tenants, invoking interaction to resolve.");
        return this.msalBroadcastService.inProgress$.pipe((0, import_operators.filter)((status) => status === InteractionStatus.None), (0, import_operators.take)(1), (0, import_operators.switchMap)(() => this.acquireTokenInteractively(authRequest, scopes)));
      }
      return (0, import_rxjs.of)(result);
    }));
  }
  /**
   * Invoke interaction for the given set of scopes
   * @param authRequest Request
   * @param scopes Array of scopes for the request
   * @returns Result from the interactive request
   */
  acquireTokenInteractively(authRequest, scopes) {
    if (this.msalInterceptorConfig.interactionType === InteractionType.Popup) {
      this.authService.getLogger().verbose("Interceptor - error acquiring token silently, acquiring by popup");
      return this.authService.acquireTokenPopup(Object.assign(Object.assign({}, authRequest), {
        scopes
      }));
    }
    this.authService.getLogger().verbose("Interceptor - error acquiring token silently, acquiring by redirect");
    const redirectStartPage = window.location.href;
    this.authService.acquireTokenRedirect(Object.assign(Object.assign({}, authRequest), {
      scopes,
      redirectStartPage
    }));
    return import_rxjs.EMPTY;
  }
  /**
   * Looks up the scopes for the given endpoint from the protectedResourceMap
   * @param endpoint Url of the request
   * @param httpMethod Http method of the request
   * @returns Array of scopes, or null if not found
   *
   */
  getScopesForEndpoint(endpoint, httpMethod) {
    this.authService.getLogger().verbose("Interceptor - getting scopes for endpoint");
    const normalizedEndpoint = this.location.normalize(endpoint);
    const protectedResourcesArray = Array.from(this.msalInterceptorConfig.protectedResourceMap.keys());
    const matchingProtectedResources = this.matchResourcesToEndpoint(protectedResourcesArray, normalizedEndpoint);
    if (matchingProtectedResources.length > 0) {
      return this.matchScopesToEndpoint(this.msalInterceptorConfig.protectedResourceMap, matchingProtectedResources, httpMethod);
    }
    return null;
  }
  /**
   * Finds resource endpoints that match request endpoint
   * @param protectedResourcesEndpoints
   * @param endpoint
   * @returns
   */
  matchResourcesToEndpoint(protectedResourcesEndpoints, endpoint) {
    const matchingResources = [];
    protectedResourcesEndpoints.forEach((key) => {
      const normalizedKey = this.location.normalize(key);
      const absoluteKey = this.getAbsoluteUrl(normalizedKey);
      const keyComponents = new URL(absoluteKey);
      const absoluteEndpoint = this.getAbsoluteUrl(endpoint);
      const endpointComponents = new URL(absoluteEndpoint);
      if (this.checkUrlComponents(keyComponents, endpointComponents)) {
        matchingResources.push(key);
      }
    });
    return matchingResources;
  }
  /**
   * Compares URL segments between key and endpoint
   * @param key
   * @param endpoint
   * @returns
   */
  checkUrlComponents(keyComponents, endpointComponents) {
    const urlProperties = ["protocol", "host", "pathname", "search", "hash"];
    for (const property of urlProperties) {
      if (keyComponents[property]) {
        const decodedInput = decodeURIComponent(keyComponents[property]);
        if (!StringUtils.matchPattern(decodedInput, endpointComponents[property])) {
          return false;
        }
      }
    }
    return true;
  }
  /**
   * Transforms relative urls to absolute urls
   * @param url
   * @returns
   */
  getAbsoluteUrl(url) {
    const link = this._document.createElement("a");
    link.href = url;
    return link.href;
  }
  /**
   * Finds scopes from first matching endpoint with HTTP method that matches request
   * @param protectedResourceMap Protected resource map
   * @param endpointArray Array of resources that match request endpoint
   * @param httpMethod Http method of the request
   * @returns
   */
  matchScopesToEndpoint(protectedResourceMap, endpointArray, httpMethod) {
    const allMatchedScopes = [];
    endpointArray.forEach((matchedEndpoint) => {
      const scopesForEndpoint = [];
      const methodAndScopesArray = protectedResourceMap.get(matchedEndpoint);
      if (methodAndScopesArray === null) {
        allMatchedScopes.push(null);
        return;
      }
      methodAndScopesArray.forEach((entry) => {
        if (typeof entry === "string") {
          scopesForEndpoint.push(entry);
        } else {
          const normalizedRequestMethod = httpMethod.toLowerCase();
          const normalizedResourceMethod = entry.httpMethod.toLowerCase();
          if (normalizedResourceMethod === normalizedRequestMethod) {
            if (entry.scopes === null) {
              allMatchedScopes.push(null);
            } else {
              entry.scopes.forEach((scope) => {
                scopesForEndpoint.push(scope);
              });
            }
          }
        }
      });
      if (scopesForEndpoint.length > 0) {
        allMatchedScopes.push(scopesForEndpoint);
      }
    });
    if (allMatchedScopes.length > 0) {
      if (allMatchedScopes.length > 1) {
        this.authService.getLogger().warning("Interceptor - More than 1 matching scopes for endpoint found.");
      }
      return allMatchedScopes[0];
    }
    return null;
  }
};
MsalInterceptor.ɵfac = function MsalInterceptor_Factory(__ngFactoryType__) {
  return new (__ngFactoryType__ || MsalInterceptor)(ɵɵinject(MSAL_INTERCEPTOR_CONFIG), ɵɵinject(MsalService), ɵɵinject(Location), ɵɵinject(MsalBroadcastService), ɵɵinject(DOCUMENT));
};
MsalInterceptor.ɵprov = ɵɵdefineInjectable({
  token: MsalInterceptor,
  factory: MsalInterceptor.ɵfac
});
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(MsalInterceptor, [{
    type: Injectable
  }], function() {
    return [{
      type: void 0,
      decorators: [{
        type: Inject,
        args: [MSAL_INTERCEPTOR_CONFIG]
      }]
    }, {
      type: MsalService
    }, {
      type: Location
    }, {
      type: MsalBroadcastService
    }, {
      type: void 0,
      decorators: [{
        type: Inject,
        args: [DOCUMENT]
      }]
    }];
  }, null);
})();
var MsalRedirectComponent = class {
  constructor(authService) {
    this.authService = authService;
  }
  ngOnInit() {
    this.authService.getLogger().verbose("MsalRedirectComponent activated");
    this.authService.handleRedirectObservable().subscribe();
  }
};
MsalRedirectComponent.ɵfac = function MsalRedirectComponent_Factory(__ngFactoryType__) {
  return new (__ngFactoryType__ || MsalRedirectComponent)(ɵɵdirectiveInject(MsalService));
};
MsalRedirectComponent.ɵcmp = ɵɵdefineComponent({
  type: MsalRedirectComponent,
  selectors: [["app-redirect"]],
  standalone: false,
  decls: 0,
  vars: 0,
  template: function MsalRedirectComponent_Template(rf, ctx) {
  },
  encapsulation: 2
});
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(MsalRedirectComponent, [{
    type: Component,
    args: [{
      selector: "app-redirect",
      template: ""
    }]
  }], function() {
    return [{
      type: MsalService
    }];
  }, null);
})();
var MsalModule = class _MsalModule {
  static forRoot(msalInstance, guardConfig, interceptorConfig) {
    return {
      ngModule: _MsalModule,
      providers: [{
        provide: MSAL_INSTANCE,
        useValue: msalInstance
      }, {
        provide: MSAL_GUARD_CONFIG,
        useValue: guardConfig
      }, {
        provide: MSAL_INTERCEPTOR_CONFIG,
        useValue: interceptorConfig
      }, MsalService]
    };
  }
};
MsalModule.ɵfac = function MsalModule_Factory(__ngFactoryType__) {
  return new (__ngFactoryType__ || MsalModule)();
};
MsalModule.ɵmod = ɵɵdefineNgModule({
  type: MsalModule,
  declarations: [MsalRedirectComponent],
  imports: [CommonModule]
});
MsalModule.ɵinj = ɵɵdefineInjector({
  providers: [MsalGuard, MsalBroadcastService],
  imports: [CommonModule]
});
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(MsalModule, [{
    type: NgModule,
    args: [{
      declarations: [MsalRedirectComponent],
      imports: [CommonModule],
      providers: [MsalGuard, MsalBroadcastService]
    }]
  }], null, null);
})();
var MsalCustomNavigationClient = class extends NavigationClient {
  constructor(authService, router, location) {
    super();
    this.authService = authService;
    this.router = router;
    this.location = location;
  }
  navigateInternal(url, options) {
    const _super = Object.create(null, {
      navigateInternal: {
        get: () => super.navigateInternal
      }
    });
    return __awaiter(this, void 0, void 0, function* () {
      this.authService.getLogger().trace("MsalCustomNavigationClient called");
      this.authService.getLogger().verbose("MsalCustomNavigationClient - navigating");
      this.authService.getLogger().verbosePii(`MsalCustomNavigationClient - navigating to url: ${url}`);
      if (options.noHistory) {
        return _super.navigateInternal.call(this, url, options);
      } else {
        const urlComponents = new UrlString(url).getUrlComponents();
        const newUrl = urlComponents.QueryString ? `${urlComponents.AbsolutePath}?${urlComponents.QueryString}` : this.location.normalize(urlComponents.AbsolutePath);
        yield this.router.navigateByUrl(newUrl, {
          replaceUrl: options.noHistory
        });
      }
      return Promise.resolve(options.noHistory);
    });
  }
};
MsalCustomNavigationClient.ɵfac = function MsalCustomNavigationClient_Factory(__ngFactoryType__) {
  return new (__ngFactoryType__ || MsalCustomNavigationClient)(ɵɵinject(MsalService), ɵɵinject(Router), ɵɵinject(Location));
};
MsalCustomNavigationClient.ɵprov = ɵɵdefineInjectable({
  token: MsalCustomNavigationClient,
  factory: MsalCustomNavigationClient.ɵfac
});
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(MsalCustomNavigationClient, [{
    type: Injectable
  }], function() {
    return [{
      type: MsalService
    }, {
      type: Router
    }, {
      type: Location
    }];
  }, null);
})();
export {
  MSAL_BROADCAST_CONFIG,
  MSAL_GUARD_CONFIG,
  MSAL_INSTANCE,
  MSAL_INTERCEPTOR_CONFIG,
  MsalBroadcastService,
  MsalCustomNavigationClient,
  MsalGuard,
  MsalInterceptor,
  MsalModule,
  MsalRedirectComponent,
  MsalService,
  version3 as version
};
/*! Bundled license information:

@azure/msal-common/dist/utils/Constants.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/AuthErrorCodes.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/AuthError.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/ClientAuthErrorCodes.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/ClientAuthError.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/crypto/ICrypto.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/logger/Logger.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/packageMetadata.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/authority/AuthorityOptions.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/account/AuthToken.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/utils/TimeUtils.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/cache/utils/CacheHelpers.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/ClientConfigurationErrorCodes.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/ClientConfigurationError.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/utils/StringUtils.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/request/ScopeSet.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/account/ClientInfo.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/account/AccountInfo.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/authority/AuthorityType.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/account/TokenClaims.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/authority/ProtocolMode.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/cache/entities/AccountEntity.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/utils/UrlUtils.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/url/UrlString.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/authority/AuthorityMetadata.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/CacheErrorCodes.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/CacheError.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/cache/CacheManager.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/config/ClientConfiguration.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/account/CcsCredential.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/constants/AADServerParamKeys.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/request/RequestValidator.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/request/RequestParameterBuilder.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/authority/OpenIdConfigResponse.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/authority/CloudInstanceDiscoveryResponse.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/authority/CloudInstanceDiscoveryErrorResponse.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/telemetry/performance/PerformanceEvent.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/utils/FunctionWrappers.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/authority/RegionDiscovery.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/authority/Authority.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/authority/AuthorityFactory.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/ServerError.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/network/ThrottlingUtils.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/NetworkError.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/client/BaseClient.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/InteractionRequiredAuthErrorCodes.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/InteractionRequiredAuthError.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/utils/ProtocolUtils.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/crypto/PopTokenGenerator.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/cache/persistence/TokenCacheContext.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/response/ResponseHandler.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/utils/ClientAssertionUtils.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/client/AuthorizationCodeClient.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/client/RefreshTokenClient.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/client/SilentFlowClient.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/network/INetworkModule.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/request/AuthenticationHeaderParser.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/telemetry/server/ServerTelemetryManager.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/JoseHeaderErrorCodes.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/error/JoseHeaderError.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/crypto/JoseHeader.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/telemetry/performance/StubPerformanceClient.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/telemetry/performance/PerformanceClient.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-common/dist/index-browser.mjs:
  (*! @azure/msal-common v15.2.0 2025-02-18 *)

@azure/msal-browser/dist/error/BrowserAuthErrorCodes.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/error/BrowserAuthError.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/utils/BrowserConstants.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/encode/Base64Encode.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/encode/Base64Decode.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/crypto/BrowserCrypto.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/error/BrowserConfigurationAuthErrorCodes.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/error/BrowserConfigurationAuthError.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/utils/BrowserUtils.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/navigation/NavigationClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/network/FetchClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/config/Configuration.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/packageMetadata.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/operatingcontext/BaseOperatingContext.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/naa/BridgeStatusCode.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/naa/BridgeProxy.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/operatingcontext/NestedAppOperatingContext.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/operatingcontext/StandardOperatingContext.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/cache/DatabaseStorage.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/cache/MemoryStorage.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/cache/AsyncMemoryStorage.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/crypto/CryptoOps.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/cache/CookieStorage.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/cache/CacheHelpers.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/cache/LocalStorage.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/cache/SessionStorage.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/utils/BrowserProtocolUtils.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/event/EventType.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/cache/BrowserCacheManager.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/cache/AccountManager.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/event/EventHandler.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_client/BaseInteractionClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/crypto/PkceGenerator.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/request/RequestHelpers.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_client/StandardInteractionClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/error/NativeAuthErrorCodes.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/broker/nativeBroker/NativeStatusCodes.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/error/NativeAuthError.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_client/SilentCacheClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_client/NativeInteractionClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/broker/nativeBroker/NativeMessageHandler.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_handler/InteractionHandler.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/response/ResponseHandler.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_client/PopupClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_handler/RedirectHandler.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_client/RedirectClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_handler/SilentHandler.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_client/SilentIframeClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_client/SilentRefreshClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/cache/TokenCache.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_client/HybridSpaAuthorizationCodeClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/interaction_client/SilentAuthCodeClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/controllers/StandardController.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/naa/BridgeError.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/naa/mapping/NestedAppAuthAdapter.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/error/NestedAppAuthError.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/controllers/NestedAppAuthController.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/controllers/ControllerFactory.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/app/PublicClientApplication.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/controllers/UnknownOperatingContextController.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/operatingcontext/UnknownOperatingContext.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/app/PublicClientNext.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/app/IPublicClientApplication.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/event/EventMessage.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/crypto/SignedHttpRequest.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/telemetry/BrowserPerformanceClient.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)

@azure/msal-browser/dist/index.mjs:
  (*! @azure/msal-browser v4.5.0 2025-02-26 *)
*/
//# sourceMappingURL=@azure_msal-angular.js.map
