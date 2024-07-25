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
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Interceptor struct {
	IAMHost      string
	IAMClient    iam_client.IamClient
	logger       *zap.Logger
	EscapePrefix string
	serviceId    string
}

func (i *Interceptor) KeycloakInterceptorFunc(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		i.logger.Error("can't get metadata FromIncomingContext")
		return handler(ctx, req)
	}
	if len(md["requesturi"]) > 0 && strings.HasPrefix(md["requesturi"][0], i.EscapePrefix) {
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
		md = i.setUserCookies(md, tokenIdResponse, tokenIdResponse.Ttl)
		_, err = url.ParseRequestURI(finalBackUrl[0])
		if err != nil {
			i.logger.Error("can't ParseRequestURI before setting cookies: %s", zap.Error(err))
			return status.New(codes.InvalidArgument, "incorrect finalBackURL"), err
		}
		return i.returnRedirectJSON(ctx, md, finalBackUrl[0])
	}

	// URL, на который IAM вернет пользователя после успешной аутентифицикации
	backURL := md[keycloak.ParamName_BackURL]
	if len(backURL) == 0 || backURL[0] == "" {
		returnStatus := status.New(codes.InvalidArgument, "bad backURL param")

		i.logger.Error("can't parse backURL")
		return returnStatus, returnStatus.Err()
	}

	// Проверяем id токена в куках
	tokenIdArr := md[keycloak.CookieName_TokenId]
	if len(tokenIdArr) == 0 || tokenIdArr[0] == "" {
		// Куки нет, дергаем ручку IAM getAuthLink и отдаем 401 со ссылкой в ответе
		authLinkResponse, err := i.IAMClient.GetAuthLink(backURL[0])
		if err != nil {
			return status.New(codes.Internal, "can't GetAuthLink"), nil
		}

		return i.returnRedirectJSON(ctx, md, authLinkResponse.RedirectUrl)
	}

	// Кука есть - запрашиваем у IAM пермишены по ручке getTokenPermissions
	tokenId, err := url.QueryUnescape(tokenIdArr[0])
	if err != nil {
		i.logger.Error("can't QueryUnescape tokenId %s", zap.Error(err))
		return status.New(codes.Internal, "can't QueryUnescape tokenId %s"), nil
	}

	resp, err := i.IAMClient.GetTokenPermissions(tokenId, i.serviceId, backURL[0])
	if err != nil {
		return status.New(codes.Internal, "can't GetTokenPermissions"), nil
	}

	// Отправляем юзера на аутентификацию в IAM
	if resp.HttpStatus == http.StatusUnauthorized {
		return i.returnRedirectJSON(ctx, md, resp.RedirectUrl)
	}

	// Все хорошо, кладем права в контекст и идем дальше
	if resp.HttpStatus == http.StatusOK {
		r = r.WithContext(context.WithValue(r.Context(), CtxIamPermissions{}, resp.Permissions))

		// Добавляем содержимое куки CookieName_UserEmail как userId
		var userEmail string
		userEmailCk, err := r.Cookie(CookieName_UserEmail)
		if err != nil {
			// Такого быть не должно ругнемся в лог
			s.log.Errorf("No cookie %s", CookieName_UserEmail)
		} else {
			userEmail, err = url.QueryUnescape(userEmailCk.Value)
			if err != nil {
				s.log.Errorf("6k5X83JDf2cI11V %s", err)
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), CtxIamUserId{}, userEmail))

		next.ServeHTTP(w, r)
		return
	}

	// Получен не 200 и не 401, отдаем статус как есть
	w.WriteHeader(resp.HttpStatus)
}

// returnRedirectJSON creates an UnauthorizedResponse with a redirect URL.
func (i *Interceptor) returnRedirectJSON(ctx context.Context, md metadata.MD, redirectUrl string) (*proto.RedirectResponse, error) {
	statusError := status.New(codes.Unauthenticated, "redirect to keycloak")
	grpc.SetHeader(ctx, metadata.Pairs("x-http-status-code", strconv.Itoa(http.StatusTemporaryRedirect)))

	st, _ := status.New(codes.Unauthenticated, "redirect").WithDetails(&proto.RedirectResponse{
		RedirectUrl: redirectUrl,
		Cookies:     md.Get("Set-Cookie")})
	return nil, st.Err()
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

	param := fmt.Sprintf("%s=%s", keycloak.ParamName_BackURL, url.QueryEscape(ref))
	if strings.Contains(uri, "?") {
		uri += "&" + param
	} else {
		uri += "?" + param
	}

	return uri
}

// setUserCookies sets user cookies in a grpc metadata
func (i *Interceptor) setUserCookies(md metadata.MD, parsedToken iam_client.IAMGetTokenIdResponse, maxAge int) metadata.MD {
	// Helper function to create cookie string
	createCookie := func(name, value string, maxage int, httpOnly bool) string {
		cookie := fmt.Sprintf("%s=%s; Max-Age=%d", name, url.QueryEscape(value), maxage)
		if httpOnly {
			cookie += "; HttpOnly"
		}
		return cookie
	}

	// Set cookies in metadata
	md.Append("Set-Cookie", createCookie(keycloak.CookieName_UserEmail, parsedToken.UserEmail, maxAge, false))
	md.Append("Set-Cookie", createCookie(keycloak.CookieName_UserName, parsedToken.UserName, maxAge, false))
	md.Append("Set-Cookie", createCookie(keycloak.CookieName_TokenId, parsedToken.Id, maxAge, true))

	return md
}
