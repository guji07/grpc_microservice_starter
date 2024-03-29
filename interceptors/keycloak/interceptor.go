package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	proto "github.com/guji07/grpc_microservice_starter/proto"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Interceptor struct {
	keycloakService *Service
	EscapePrefix    string
}

func NewInterceptor(keycloakService *Service, escapePrefix string) *Interceptor {
	return &Interceptor{keycloakService: keycloakService, EscapePrefix: escapePrefix}
}

func (i *Interceptor) KeycloakInterceptorFunc(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if !i.keycloakService.config.IsEnabled {
		return handler(ctx, req)
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return handler(ctx, req)
	}
	if len(md["requesturi"]) > 0 && strings.HasPrefix(md["requesturi"][0], i.EscapePrefix) {
		return handler(ctx, req)
	}
	// 1. Check token-uuid in cookies
	if i.isTokenInCookiesOk(ctx, md) {
		return handler(ctx, req)
	}
	// 2. If no cookies or error in checking the token, check if it's a request after a redirect from KeyCloak
	// 2.1. Check KeyCloak parameters
	params := i.getParams(md)
	if params.Code == "" || params.State == "" || !i.keycloakService.CheckState(params.State) {
		// This is not a request after a redirect from KeyCloak, redirect the user to authentication
		return i.returnRedirectJSON(ctx, md, "")
	}

	// 2.2. Try to get the token...
	token, err := i.keycloakService.GetToken(ctx, params.Code, i.getRedirectURI(md))
	if err != nil {
		i.keycloakService.logger.Error("getToken", zap.Error(err))
		return i.returnRedirectJSON(ctx, md, "")
	}

	// 2.3. Got the token. Check it...
	var parsedToken *ParsedToken
	ctx, parsedToken, err = i.checkAndSaveToken(ctx, token.IDToken)
	if err != nil {
		i.keycloakService.logger.Error("checkAndSaveToken", zap.Error(err))
		return i.returnRedirectJSON(ctx, md, "")
	}

	// 2.4. Token is valid. Save user cookies
	// * save user cookies
	md, err = i.setUserCookies(md, parsedToken, token.ExpiresIn)
	if err != nil {
		i.keycloakService.logger.Error("setUserCookies", zap.Error(err))
		return i.returnRedirectJSON(ctx, md, "")
	}
	// * save token in storage
	i.keycloakService.storage.Set(ctx, parsedToken.UUID, token.IDToken, token.ExpiresIn)
	// * return redirect to the original URL
	backURL := i.getBackURL(md)
	return i.returnRedirectJSON(ctx, md, backURL)
}

// getBackURL returns the back URL, either from the GET parameter or from the config.
func (i *Interceptor) getBackURL(md metadata.MD) string {
	// Extract back URL from metadata
	values := md.Get(ParamName_BackURL)
	if len(values) == 0 {
		// Back URL not found in metadata, return default back URL from config
		return i.keycloakService.config.BackURL
	}

	return values[0] // Return the first value of the back URL parameter
}

// isTokenInCookiesOk checks if the token in cookies is valid in a gRPC context.
func (i *Interceptor) isTokenInCookiesOk(ctx context.Context, md metadata.MD) bool {
	uuidCks := ""
	cookies, ok := md["grpcgateway-cookie"]
	if !ok || len(cookies) == 0 {
		// metadata cookie not found
		return false
	}
	cookiesArray := strings.Split(cookies[0], ";")
	for _, v := range cookiesArray {
		if strings.Contains(v, CookieName_UUID) {
			_, uuidCks, _ = strings.Cut(v, "=")
		}
	}

	uuidCkStr, err := url.QueryUnescape(uuidCks)
	if err != nil {
		// Found the cookie, but error in decoding
		i.keycloakService.logger.Error("url.QueryUnescape", zap.Error(err))
		return false
	}

	// UUID found in cookies, check the storage for the token
	tokenCk, found := i.keycloakService.storage.Get(ctx, uuidCkStr)
	if !found {
		return false
	}

	// Check the token (assuming checkAndSaveToken is adapted for gRPC)
	_, _, err = i.checkAndSaveToken(ctx, tokenCk) // This function needs to be adapted for gRPC
	if err != nil {
		i.keycloakService.logger.Error("checkAndSaveToken", zap.Error(err))
		return false
	}

	return true
}

// checkAndSaveToken checks and saves the token in a gRPC context.
func (i *Interceptor) checkAndSaveToken(ctx context.Context, token string) (context.Context, *ParsedToken, error) {
	parsedToken, err := i.keycloakService.parseToken(ctx, token) // Assuming parseToken is adapted for gRPC
	if err != nil {
		return ctx, nil, err
	}

	accessToken, claims, err := i.keycloakService.DecodeAccessToken(ctx, token) // Assuming DecodeAccessToken is adapted for gRPC
	if err != nil {
		return ctx, nil, errors.WithStack(err)
	}
	if !accessToken.Valid {
		return ctx, nil, errors.New("token is not valid")
	}

	// Add claims to the context
	ctx = context.WithValue(ctx, CtxUserValue_Claims, claims)

	// Optionally, you could use metadata to carry information like user email, but it's usually better to keep it in context for internal use
	str := fmt.Sprintf("%s", parsedToken.UserEmail)
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	}
	md.Append("x-user-email", str)
	newCtx := metadata.NewOutgoingContext(ctx, md)

	return newCtx, parsedToken, nil
}

func (i *Interceptor) getParams(md metadata.MD) (params *getTokenParams) {
	params = &getTokenParams{}

	if values := md.Get(ParamName_State); len(values) > 0 {
		params.State = values[0]
	}
	if values := md.Get(ParamName_Code); len(values) > 0 {
		params.Code = values[0]
	}
	if values := md.Get(ParamName_SessionState); len(values) > 0 {
		params.SessionState = values[0]
	}

	return params
}

// returnRedirectJSON creates an UnauthorizedResponse with a redirect URL.
func (i *Interceptor) returnRedirectJSON(ctx context.Context, md metadata.MD, providedBackURL string) (*proto.RedirectResponse, error) {
	statusError := status.New(codes.Unauthenticated, "redirect to keycloak")
	if providedBackURL != "" {
		grpc.SetHeader(ctx, metadata.Pairs("x-http-status-code", strconv.Itoa(http.StatusTemporaryRedirect)))

		st, _ := status.New(codes.Unauthenticated, "redirect to back_url").WithDetails(&proto.RedirectResponse{
			RedirectUrl: providedBackURL,
			Cookies:     md.Get("Set-Cookie")})
		return nil, st.Err()
	}
	grpc.SetHeader(ctx, metadata.Pairs("x-http-status-code", strconv.Itoa(http.StatusUnauthorized)))
	backURL := i.getRedirectURI(md) // Assuming getRedirectURI is adapted for gRPC
	u := i.keycloakService.GenerateAuthLink(backURL)
	st, _ := statusError.WithDetails(&proto.RedirectResponse{RedirectUrl: u}, &proto.RedirectResponse{})

	return nil, st.Err()
}

type UnauthorizedResponse struct {
	RedirectURL string `json:"redirect_url"`
}

// getRedirectURI returns the URL to which the user should be redirected after successful authentication in Keycloak.
func (i *Interceptor) getRedirectURI(md metadata.MD) string {
	// Extract the original request URI from metadata
	uri := ""
	if values := md.Get("X-Original-Request-Uri"); len(values) > 0 {
		uri = values[0]
	}
	if uri == "" {
		// Fallback if the original URI is not set
		if reqUri := md.Get("RequestURI")[0]; len(reqUri) > 0 {
			uri = md.Get("RequestURI")[0]
		}
	}

	uri = i.addBackURL(md, uri)

	// Extract the host from metadata, or use a default host
	host := "" // Replace with your default or extract from metadata
	if values, ok := md["x-forwarded-host"]; ok && len(values) > 0 {
		host = values[0]
	}

	return "https://" + strings.Trim(host, "/") + uri
}

// addBackURL adds a backURL parameter to the URI.
func (i *Interceptor) addBackURL(md metadata.MD, uri string) string {
	// Extract the referer from metadata
	ref := ""
	if values, ok := md["grpcgateway-referer"]; ok && len(values) > 0 {
		ref = values[0]
	}
	if ref == "" {
		return uri
	}

	param := fmt.Sprintf("%s=%s", ParamName_BackURL, url.QueryEscape(ref))
	if strings.Contains(uri, "?") {
		uri += "&" + param
	} else {
		uri += "?" + param
	}

	return uri
}

// setUserCookies sets user cookies in a grpc metadata
func (i *Interceptor) setUserCookies(md metadata.MD, parsedToken *ParsedToken, maxAge int) (metadata.MD, error) {
	// Helper function to create cookie string
	createCookie := func(name, value string, maxage int, httpOnly bool) string {
		cookie := fmt.Sprintf("%s=%s; Max-Age=%d", name, url.QueryEscape(value), maxage)
		if httpOnly {
			cookie += "; HttpOnly"
		}
		return cookie
	}

	// Set cookies in metadata
	md.Append("Set-Cookie", createCookie(CookieName_UserEmail, parsedToken.UserEmail, maxAge, false))
	md.Append("Set-Cookie", createCookie(CookieName_UserName, parsedToken.UserName, maxAge, false))
	md.Append("Set-Cookie", createCookie(CookieName_UUID, parsedToken.UUID, maxAge, true))

	return md, nil
}
