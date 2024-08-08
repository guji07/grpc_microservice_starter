package http_mapping

const (
	CookieName_UUID             = "oidc_token_uuid"
	CookieName_UserEmail        = "UserEmail"
	CookieName_UserName         = "UserName"
	CookieName_TokenId          = "iam_token_id"
	CtxUserValue_Claims         = "claims"
	grantType_AuthorizationCode = "authorization_code"

	ParamName_SessionState = "session_state"
	ParamName_Locale       = "locale"
	ParamName_State        = "state"
	ParamName_Code         = "code"
	ParamName_BackURL      = "backurl"
	//HEADERS:
	//HEADERS ARE CASE INSENSITIVE BY HTTP PROTOCOL, SO ALWAYS USE strings.ToLower WHEN PUTTING AND ACCESSING HEADERS FROM METADATA
	ParamName_XAccessToken        = "x-access-token"
	ParamName_XAccessKey          = "x-access-key"
	ParamName_XOriginalRequestURI = "x-original-request-uri"

	ParamName_FinalBackUrl = "finalBackURL"

	//already proxying by default grpc-gateway behaviour:
	//queryParams, CASE SENSITIVE
	ParamName_Host       = "x-forwarded-host"
	ParamName_RequestURI = "requesturi"
	ParamName_Referer    = "grpcgateway-referer"
	ParamName_Cookies    = "grpcgateway-cookie"

	//Metadata tags:
	MetadataName_IAMPermissions = "iam_permissions"
	MetadataName_IAMUserId      = "iam_user_id"
)

var (
	HeaderParams = []string{ParamName_XOriginalRequestURI, ParamName_XAccessKey, ParamName_XAccessToken}
)
