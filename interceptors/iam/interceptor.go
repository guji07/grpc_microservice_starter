package iam

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/guji07/grpc_microservice_starter/interceptors/keycloak"
	proto "github.com/guji07/grpc_microservice_starter/proto"
	"github.com/happywbfriends/iam_client"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Interceptor struct {
	IAMClient    *iam_client.IamClient
	logger       *zap.Logger
	EscapePrefix string
	serviceId    string
}

func NewInterceptor(IAMClient *iam_client.IamClient, logger *zap.Logger, escapePrefix string, serviceId string) *Interceptor {
	return &Interceptor{IAMClient: IAMClient, logger: logger, EscapePrefix: escapePrefix, serviceId: serviceId}
}

func (i *Interceptor) IamInterceptorFunc(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		i.logger.Error("can't get metadata FromIncomingContext")
		return handler(ctx, req)
	}

	//0. если урл принадлежит исключениям(i.EscapePrefix), то скипаем авторизацию
	if len(md[keycloak.ParamName_RequestURI]) > 0 && strings.HasPrefix(md[keycloak.ParamName_RequestURI][0], i.EscapePrefix) {
		return handler(ctx, req)
	}

	// 1. Аутентификация приложения по ключу доступа (app2app)
	if processed, err := i.AuthAccessKey(ctx, req, handler); processed {
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}

	code := md[keycloak.ParamName_Code]
	finalBackUrl := md[keycloak.ParamName_FinalBackUrl]

	// Шаг 2. Аутентификация пользователя (user2app)
	// Если это запрос после аутентификации в IAM, обрабатываем его
	if len(code) != 0 && len(finalBackUrl) != 0 && code[0] != "" && finalBackUrl[0] != "" {
		tokenIdResponse, err := i.IAMClient.GetTokenId(code[0])
		if err != nil {
			return status.New(codes.Internal, "can't GetAuthLink"), err
		}
		md = setUserCookies(md, tokenIdResponse)
		_, err = url.ParseRequestURI(finalBackUrl[0])
		if err != nil {
			i.logger.Error("can't ParseRequestURI before setting cookies: %s", zap.Error(err))
			return status.New(codes.InvalidArgument, "incorrect finalBackURL"), err
		}
		return i.returnRedirectJSON(ctx, md, finalBackUrl[0], http.StatusTemporaryRedirect)
	}

	// URL, на который IAM вернет пользователя после успешной аутентифицикации
	backURL, err := i.getBackURL(md)
	if err != nil || backURL == "" {
		returnStatus := status.New(codes.Internal, "can't get backURL")
		i.logger.Error("can't get backURL")
		return returnStatus, returnStatus.Err()
	}

	// есть ли id токена в куке
	tokenIdArr := i.getFromCookie(ctx, md, keycloak.CookieName_TokenId)
	if tokenIdArr == "" {
		// Куки нет, дергаем ручку IAM getAuthLink и отдаем 401 со ссылкой в ответе
		authLinkResponse, err := i.IAMClient.GetAuthLink(backURL)
		if err != nil {
			return status.New(codes.Internal, "can't GetAuthLink"), nil
		}

		return i.returnRedirectJSON(ctx, md, authLinkResponse.RedirectUrl, http.StatusUnauthorized)
	}

	// Кука есть - запрашиваем у IAM пермишены по ручке getTokenPermissions
	tokenId, err := url.QueryUnescape(tokenIdArr)
	if err != nil {
		i.logger.Error("can't QueryUnescape tokenId %s", zap.Error(err))
		return status.New(codes.Internal, "can't QueryUnescape tokenId %s"), nil
	}

	resp, err := i.IAMClient.GetTokenPermissions(tokenId, i.serviceId, backURL)
	if err != nil {
		return status.New(codes.Internal, "can't GetTokenPermissions"), nil
	}

	// Отправляем юзера на аутентификацию в IAM
	if resp.HttpStatus == http.StatusUnauthorized {
		return i.returnRedirectJSON(ctx, md, resp.RedirectUrl, http.StatusUnauthorized)
	}

	// Все хорошо, кладем права в контекст и идем дальше
	if resp.HttpStatus == http.StatusOK {
		md.Set(keycloak.MetadataName_IAMPermissions, resp.Permissions...)
		md.Set(keycloak.MetadataName_IAMUserId, resp.UserId)

		// Добавляем содержимое куки CookieName_UserEmail как userId
		var userEmail string
		userEmailCk := md.Get(keycloak.CookieName_UserEmail)
		if len(userEmailCk) < 1 {
			// Такого быть не должно ругнемся в лог
			i.logger.Error("No UserEmail cookies :(")
		} else {
			userEmail, err = url.QueryUnescape(userEmailCk[0])
			if err != nil {
				i.logger.Error("can't parse UserEmail cookies :(")
			}
		}
		md.Set(keycloak.MetadataName_IAMUserId, userEmail)

		return handler(ctx, req)
	}

	// Получен не 200 и не 401, отдаем статус как есть
	return nil, status.Error(codes.Internal, "received not 200 from iam when getting user permissions")
}

func (i *Interceptor) getFromCookie(ctx context.Context, md metadata.MD, cookieName string) string {
	var value string
	cookies := md.Get(keycloak.ParamName_Cookies)

	if len(cookies) == 0 {
		return ""
	}
	cookiesArray := strings.Split(cookies[0], ";")
	for _, v := range cookiesArray {
		if strings.Contains(v, cookieName) {
			_, value, _ = strings.Cut(v, "=")
			return value
		}
	}

	return value
}

// AuthAccessKey аутентифицирует приложение по хедеру X-Access-Key
// Если хедер присутствуют, полностью берет обработку на себя, в этом случае возвращает true
func (i *Interceptor) AuthAccessKey(ctx context.Context, req interface{}, handler grpc.UnaryHandler) (processed bool, err error) {
	// Проверяем наличие хедеров X-Access-Key
	md, _ := metadata.FromIncomingContext(ctx)
	var accessKey string
	accessKeys := md.Get(keycloak.ParamName_XAccessKey)
	if len(accessKeys) < 1 {
		return false, nil
	}
	accessKey = accessKeys[0]
	if accessKey == "" {
		return
	}

	// Ключ в хедере есть, полностью берем обработку запроса на себя
	processed = true

	// Запрашиваем у IAM пермишены
	resp, err := i.IAMClient.GetAccessKeyPermissions(accessKey, i.serviceId)
	if err != nil || resp.HttpStatus != http.StatusOK {
		return processed, status.Error(codes.Internal, "can't check access key permissions")
	}

	md.Set("iam_permissions", resp.Permissions...)
	md.Set("iam_user_id", resp.UserId)
	return processed, nil
}

// returnRedirectJSON creates an UnauthorizedResponse with a redirect URL.
func (i *Interceptor) returnRedirectJSON(ctx context.Context, md metadata.MD, redirectUrl string, respCode int) (*proto.RedirectResponse, error) {
	_ = grpc.SetHeader(ctx, metadata.Pairs("x-http-status-code", strconv.Itoa(respCode)))
	st, _ := status.New(codes.Unauthenticated, "redirect").WithDetails(&proto.RedirectResponse{
		RedirectUrl: redirectUrl,
		Cookies:     md.Get("Set-Cookie")})
	return nil, st.Err()
}

// getRedirectURI returns the URL to which the user should be redirected after successful authentication in Keycloak.
func (i *Interceptor) getRedirectURI(md metadata.MD) string {
	// Extract the original request URI from metadata
	uri := ""
	if values := md.Get(keycloak.ParamName_XOriginalRequestURI); len(values) > 0 {
		uri = values[0]
	}
	if uri == "" {
		// Fallback if the original URI is not set
		if reqUri := md.Get(keycloak.ParamName_RequestURI)[0]; len(reqUri) > 0 {
			uri = md.Get(keycloak.ParamName_RequestURI)[0]
		}
	}

	uri = i.addBackURL(md, uri)

	// Extract the host from metadata, or use a default host
	host := "" // Replace with your default or extract from metadata
	if values, ok := md[keycloak.ParamName_Host]; ok && len(values) > 0 {
		host = values[0]
	}

	return "https://" + strings.Trim(host, "/") + uri
}

// addBackURL adds a backURL parameter to the URI.
func (i *Interceptor) addBackURL(md metadata.MD, uri string) string {
	// Extract the referer from metadata
	ref := ""
	if values, ok := md[keycloak.ParamName_Referer]; ok && len(values) > 0 {
		ref = values[0]
	}
	if ref == "" {
		return uri
	}

	param := fmt.Sprintf("%s=%s", keycloak.ParamName_BackURL, url.QueryEscape(ref))
	if strings.Contains(uri, "?") {
		uri += "&" + param
	} else {
		uri += "?" + param
	}

	return uri
}

// setUserCookies sets user cookies in a grpc metadata
func setUserCookies(md metadata.MD, parsedToken iam_client.IAMGetTokenIdResponse) metadata.MD {
	// Helper function to create cookie string

	// Set cookies in metadata
	md.Append("Set-Cookie", createCookie(keycloak.CookieName_UserEmail, parsedToken.UserEmail, parsedToken.Ttl, false))
	md.Append("Set-Cookie", createCookie(keycloak.CookieName_UserName, parsedToken.UserName, parsedToken.Ttl, false))
	md.Append("Set-Cookie", createCookie(keycloak.CookieName_TokenId, parsedToken.Id, parsedToken.Ttl, true))

	return md
}

func createCookie(name, value string, maxage int, httpOnly bool) string {
	cookie := fmt.Sprintf("%s=%s; Max-Age=%d", name, url.QueryEscape(value), maxage)
	if httpOnly {
		cookie += "; HttpOnly"
	}
	return cookie
}

var ErrEmptyReferer = errors.New("Empty referer")

// getBackURL формирует backURL, на который IAM вернет пользователя после успешной аутентифицикации
// Это ссылка на ручку вида /api/v1/REQUEST?finalBackURL=<finalBackURL>
// Где finalBackURL - это URL, на который надо будет вернуть пользователя в самом конце цепочки.
// Т.е. это URL, на котором сейчас находится пользователь, а, точнее, реферер.
func (i *Interceptor) getBackURL(md metadata.MD) (string, error) {
	// URL, на который надо будет финально вернуть пользователя в самом конце цепочки
	var finalBackURL string
	if len(md.Get(keycloak.ParamName_Referer)) > 0 {
		finalBackURL = md.Get(keycloak.ParamName_Referer)[0]
	}
	if finalBackURL == "" {
		return "", ErrEmptyReferer
	}

	// URL текущего запроса к АПИ, на него надо будет вернуть пользователя после успешной аутентифицикации в IAM
	requestURL := i.getRequestURL(md)
	if strings.Contains(requestURL, "?") {
		requestURL += "&finalBackURL=" + url.QueryEscape(finalBackURL)
	} else {
		requestURL += "?finalBackURL=" + url.QueryEscape(finalBackURL)
	}

	return requestURL, nil
}

// getRequestURL возвращает URL текущего запроса АПИ. На него надо будет вернуть
// пользователя после успешной аутентификации в IAM
func (i *Interceptor) getRequestURL(md metadata.MD) string {
	// Если передан заголовок X-Original-Request-Uri, то берем его.
	// Он м.б. установлен даунстримом, если сервис подключен с помощью proxy_pass в nginx,
	// в этом случае нам важно вернуть пользователя именно по этому URI.
	var uri string
	var host string
	xOriginalRequestUris := md.Get(keycloak.ParamName_XOriginalRequestURI)
	if len(xOriginalRequestUris) > 0 {
		uri = xOriginalRequestUris[0]
	}
	if uri == "" {
		if len(md.Get(keycloak.ParamName_RequestURI)) > 0 {
			uri = md.Get(keycloak.ParamName_RequestURI)[0]
		}
	}

	hosts := md.Get(keycloak.ParamName_Host)
	if len(hosts) > 0 {
		host = hosts[0]
	} else {
		i.logger.Error("no host in request, func getRequestURL")
	}

	return "https://" + strings.Trim(host, "/") + uri
}
