package keycloak

import (
	"context"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/golang-jwt/jwt/v5"
	"github.com/guji07/grpc_microservice_starter/interceptors/keycloak/storage"
	"github.com/pkg/errors"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

func NewService(ctx context.Context, conf *Config, logger *zap.Logger) (*Service, error) {
	stor, err := storage.NewRedisStorage(ctx, conf.RedisURL)
	if err != nil {
		return nil, err
	}
	svc := Service{
		config:         conf,
		logger:         logger,
		keyCloakClient: gocloak.NewClient("https://" + conf.Host),
		storage:        stor,
	}

	return &svc, nil
}

type Service struct {
	config         *Config
	logger         *zap.Logger
	keyCloakClient *gocloak.GoCloak
	storage        storage.TokenStorage
}

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
	ParamName_XAccessToken        = "X-Access-Token"
	ParamName_XAccessKey          = "X-Access-Key"
	ParamName_Host                = "Host"
	ParamName_XOriginalRequestURI = "X-Original-Request-Uri"

	ParamName_FinalBackUrl = "final_backurl"

	//already proxying by default grpc-gateway behaviour:
	ParamName_RequestURI = "requesturi"
	ParamName_Referer    = "grpcgateway-referer"
	ParamName_Cookies    = "grpcgateway-cookie"

	//Metadata tags:
	MetadataName_IAMPermissions = "iam_permissions"
	MetadataName_IAMUserId      = "iam_user_id"
)

var (
	HeaderParams = []string{ParamName_Host, ParamName_XOriginalRequestURI, ParamName_XAccessKey, ParamName_XAccessToken}
)

type getTokenParams struct {
	Code         string `form:"code"`
	State        string `form:"state"`
	SessionState string `form:"session_state"`
}

var getTokenParamsSlice = []string{"state", "code", "session_state"}

func (s *Service) DecodeAccessToken(ctx context.Context, token string) (*jwt.Token, *jwt.MapClaims, error) {
	return s.keyCloakClient.DecodeAccessToken(ctx, token, s.config.Realm)
}

// GenerateAuthLink генерит ссылку на KeyCloak
func (s *Service) GenerateAuthLink(redirectAuthURI string) string {
	uri := fasthttp.AcquireURI()
	uri.SetScheme("https")
	uri.SetHost(strings.Trim(s.config.Host, "/"))
	uri.SetPath("/realms/" + s.config.Realm + "/protocol/openid-connect/auth")
	uri.QueryArgs().Add("client_id", s.config.ClientID)
	uri.QueryArgs().Add("state", s.config.ClientID)
	uri.QueryArgs().Add("response_type", "code")
	uri.QueryArgs().Add("scope", "openid")
	uri.QueryArgs().Add("redirect_uri", redirectAuthURI)

	return uri.String()
}

func (s *Service) CheckState(state string) bool {
	return state == s.config.ClientID
}

// GetToken достаёт токен для обработки после редиректа из KeyCloak обратно
func (s *Service) GetToken(ctx context.Context, tokenCode, redirectURI string) (jwtToken *gocloak.JWT, err error) {
	grantType := grantType_AuthorizationCode
	redirectURI = delQueryParams(redirectURI, getTokenParamsSlice...)

	token, err := s.keyCloakClient.GetToken(ctx, s.config.Realm, gocloak.TokenOptions{
		ClientID:     &s.config.ClientID,
		ClientSecret: &s.config.ClientSecret,
		Code:         &tokenCode,
		GrantType:    &grantType,
		RedirectURI:  &redirectURI,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return token, nil
}

func delQueryParams(path string, params ...string) string {
	ix := strings.IndexByte(path, '?')
	if ix < 0 {
		return path
	}
	var ok bool
	paramsMap := make(map[string]struct{}, len(params))
	for _, p := range params {
		paramsMap[p] = struct{}{}
	}

	query := path[ix+1:]
	pairs := strings.Split(query, "&")
	newQuery := make([]string, 0, len(pairs))
	for _, p := range pairs {
		kv := strings.Split(p, "=")
		if _, ok = paramsMap[kv[0]]; !ok {
			newQuery = append(newQuery, p)
		}
	}
	b := strings.Builder{}
	b.WriteString(path[:ix])
	if len(newQuery) > 0 {
		b.WriteString("?" + strings.Join(newQuery, "&"))
	}
	res := b.String()
	return res
}
