package grpc_microservice_starter

import (
	"context"
	"net"
	"net/http"
	"net/textproto"
	"strconv"

	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_runtime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/guji07/grpc_microservice_starter/interceptors"
	"github.com/guji07/grpc_microservice_starter/interceptors/iam"
	"github.com/guji07/grpc_microservice_starter/interceptors/keycloak"
	grpc_microservice_starter "github.com/guji07/grpc_microservice_starter/proto"
	"github.com/happywbfriends/iam_client"
	wb_metrics "github.com/happywbfriends/metrics/v1"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type GrpcServerStarter struct {
	GrpcServer         *grpc.Server
	config             Config
	jaegerExporter     jaeger.Exporter
	logger             *zap.Logger
	customHttpHandlers []HttpRouteHandler
}

type HttpRouteHandler struct {
	Method  string
	Path    string
	Handler grpc_runtime.HandlerFunc
}

// NewGrpcServerStarter - main function of library
// to use library:
// create new GrpcServerStarter with Config
// register your YourController with proto.RegisterYourServiceServer(GrpcServerStarter, YourController), where proto -
//
//	name of the package with generated code
//
// start if err := GrpcServerStarter.Start(ctx, proto.RegisterYourServiceHandlerFromEndpoint); err != nil { serverStarter.Stop(ctx) }
func NewGrpcServerStarter(config Config, unaryInterceptors []grpc.UnaryServerInterceptor, customHttpHandlers []HttpRouteHandler) *GrpcServerStarter {
	logger, _ := zap.NewProduction()
	metricsUnaryInterceptor := interceptors.UnaryMetricsInterceptor(config.Server.MetricsBind, wb_metrics.NewHTTPServerMetrics(), logger)

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			initUnaryInterceptors(unaryInterceptors, config, metricsUnaryInterceptor, logger)...,
		),
		grpc.ChainStreamInterceptor(
			grpc_recovery.StreamServerInterceptor(),
			otelgrpc.StreamServerInterceptor()),
	)

	return &GrpcServerStarter{
		GrpcServer:         grpcServer,
		config:             config,
		logger:             logger,
		customHttpHandlers: customHttpHandlers,
	}
}

func initUnaryInterceptors(unaryInterceptors []grpc.UnaryServerInterceptor,
	config Config,
	metricsUnaryInterceptor func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error),
	logger *zap.Logger) []grpc.UnaryServerInterceptor {

	/*if config.Interceptor.EnableKeycloakInterceptor {
		service, err := keycloak.NewService(context.Background(), &config.Keycloak, logger)
		if err != nil {
			logger.Fatal("can't get keycloak service", zap.Error(err))
		}
		unaryInterceptors = append(unaryInterceptors, keycloak.NewInterceptor(service, config.Interceptor.EscapePrefix).KeycloakInterceptorFunc)
	}*/
	if config.Interceptor.EnableIAMInterceptor {
		iamClient := iam_client.NewIamClient(
			config.IAM.ServiceId,
			config.IAM.IAMHost,
			iam.NewLogger(logger),
			http.DefaultClient,
		)
		interceptor := iam.NewInterceptor(
			iamClient,
			logger,
			"/public/",
			config.IAM.ServiceId)
		unaryInterceptors = append(unaryInterceptors, interceptor.IamInterceptorFunc)
	}
	if config.Interceptor.EnableValidationInterceptor {
		unaryInterceptors = append(unaryInterceptors, interceptors.ValidationUnaryInterceptor(logger))
	}
	if config.Interceptor.EnableMetricsInterceptor {
		unaryInterceptors = append(unaryInterceptors, metricsUnaryInterceptor)
	}
	unaryInterceptors = append(unaryInterceptors,
		//TODO Deprecated: Use [NewServerHandler] instead.
		otelgrpc.UnaryServerInterceptor(),
		grpc_recovery.UnaryServerInterceptor())
	return unaryInterceptors
}

func (g *GrpcServerStarter) Start(ctx context.Context, registerServiceFuncsArray []func(ctx context.Context, mux *grpc_runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error)) error {
	// Set up OTLP tracing (stdout for debug).
	exp, err := g.setupJaeger()
	if err != nil {
		return err
	}
	defer func() { _ = exp.Shutdown(context.Background()) }()

	lis, err := net.Listen("tcp", g.config.Server.GrpcBind)
	if err != nil {
		g.logger.Fatal("Failed to listen:", zap.Error(err))
	}
	mux := grpc_runtime.NewServeMux(
		grpc_runtime.WithMetadata(func(_ context.Context, req *http.Request) metadata.MD {
			var localeValue = "ru"
			locale, err := req.Cookie("locale")
			if err == nil && locale != nil {
				localeValue = locale.Value
			}
			return metadata.New(map[string]string{
				//query params:
				keycloak.ParamName_State:        req.URL.Query().Get(keycloak.ParamName_State),
				keycloak.ParamName_Code:         req.URL.Query().Get(keycloak.ParamName_Code),
				keycloak.ParamName_BackURL:      req.URL.Query().Get(keycloak.ParamName_BackURL),
				keycloak.ParamName_FinalBackUrl: req.URL.Query().Get(keycloak.ParamName_FinalBackUrl),
				keycloak.ParamName_SessionState: req.URL.Query().Get(keycloak.ParamName_SessionState),

				//request uri:
				keycloak.ParamName_RequestURI: req.URL.RequestURI(),

				//headers:
				keycloak.ParamName_XAccessToken: req.Header.Get(keycloak.ParamName_XAccessToken),
				keycloak.ParamName_XAccessKey:   req.Header.Get(keycloak.ParamName_XAccessKey),

				//cookies:
				keycloak.ParamName_Locale: localeValue,
			})
		}),
		grpc_runtime.WithRoutingErrorHandler(handleRoutingError),
		//custom error handling - for example when no token to keycloak we return json with redirect_url
		grpc_runtime.WithErrorHandler(g.httpErrorHandlerFunc),
		grpc_runtime.WithIncomingHeaderMatcher(CustomMatcher),
	)
	for _, v := range g.customHttpHandlers {
		err = mux.HandlePath(v.Method, v.Path, v.Handler)
		if err != nil {
			g.logger.Fatal("error adding custom http route handler", zap.Error(err))
			return err
		}
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	for _, registerServiceFunc := range registerServiceFuncsArray {
		err = registerServiceFunc(ctx, mux, g.config.Server.GrpcBind, opts)
		if err != nil {
			return err
		}
	}

	// Serve probes
	g.startProbes()
	// Serve gRPC Server
	go func() {
		g.logger.Info("started grpc server on", zap.String("bind", g.config.Server.GrpcBind))
		err = g.GrpcServer.Serve(lis)
		if err != nil {
			g.logger.Fatal("grpc server finished", zap.Error(err))
		}
	}()

	g.logger.Info("started http gateway on", zap.String("bind", g.config.Server.HttpBind))
	err = http.ListenAndServe(g.config.Server.HttpBind, mux)
	if err != nil {
		g.logger.Fatal("http gateway finished", zap.Error(err))
	}

	return err
}

func (g *GrpcServerStarter) setupJaeger() (*jaeger.Exporter, error) {
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(g.config.JaegerUrl)))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(g.config.ServiceName),
		)),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return exp, nil
}

func (g *GrpcServerStarter) Stop(ctx context.Context) {
	err := g.jaegerExporter.Shutdown(ctx)
	if err != nil {
		g.logger.Warn("jaeger shutdown error", zap.Error(err))
		return
	}
}

func (g *GrpcServerStarter) startProbes() {
	if g.config.Server.ProbeBind == "" {
		g.logger.Error("Probes not started because bind parameter is empty")
		return
	}

	http.HandleFunc("/alive", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("ok"))
		if err != nil {
			g.logger.Error("error responding to probe", zap.Error(err))
		}
	})
	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("ok"))
		if err != nil {
			g.logger.Error("error responding to probe", zap.Error(err))
		}
	})
	g.logger.Info("started probes on", zap.String("bind", g.config.Server.ProbeBind))
	go func() {
		if err := http.ListenAndServe(g.config.Server.ProbeBind, nil); err != nil {
			g.logger.Error("listen probe failed", zap.Error(err))
		}
	}()
}

func handleRoutingError(ctx context.Context, mux *grpc_runtime.ServeMux, marshaler grpc_runtime.Marshaler, w http.ResponseWriter, r *http.Request, httpStatus int) {
	if httpStatus != http.StatusMethodNotAllowed {
		grpc_runtime.DefaultRoutingErrorHandler(ctx, mux, marshaler, w, r, httpStatus)
		return
	}

	// Use HTTPStatusError to customize the DefaultHTTPErrorHandler status code
	err := &grpc_runtime.HTTPStatusError{
		HTTPStatus: httpStatus,
		Err:        status.Error(codes.Unimplemented, http.StatusText(httpStatus)),
	}

	grpc_runtime.DefaultHTTPErrorHandler(ctx, mux, marshaler, w, r, err)
}

// function for custom http answers, in our case: redirect urls to keycloak
func (g *GrpcServerStarter) httpErrorHandlerFunc(ctx context.Context, mux *grpc_runtime.ServeMux, m grpc_runtime.Marshaler, w http.ResponseWriter, req *http.Request, err error) {
	s, ok := status.FromError(err)
	//if we see that status error is not nil we try to handle it ourselves:
	if !ok || s.Err() != nil {
		md, _ := grpc_runtime.ServerMetadataFromContext(ctx)
		statusCodes := md.HeaderMD.Get("x-http-status-code")
		if len(statusCodes) > 0 {
			code, _ := strconv.Atoi(statusCodes[0])
			switch code {
			case http.StatusTemporaryRedirect:
				{
					protoRedirect := (s.Details()[0]).(*grpc_microservice_starter.RedirectResponse)
					for _, v := range protoRedirect.Cookies {
						w.Header().Add("Set-Cookie", v)
					}
					http.Redirect(w, req, protoRedirect.RedirectUrl, http.StatusTemporaryRedirect)
					return
				}
			case http.StatusUnauthorized:
				{
					httpStatusError := grpc_runtime.HTTPStatusError{
						HTTPStatus: http.StatusUnauthorized,
						Err:        err,
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(httpStatusError.HTTPStatus)
					protoRedirect := (s.Details()[0]).(*grpc_microservice_starter.RedirectResponse)
					protoRedirect.Cookies = nil
					msg, _ := protojson.Marshal(protoRedirect)
					_, err := w.Write(msg)
					if err != nil {
						g.logger.Fatal("error writing custom http response", zap.Error(err))
					}
					return
				}
				// if we don't have handling for this code than fall to
				// grpc_runtime.DefaultHTTPErrorHandler(ctx, mux, m, w, req, err)
			}
		}
	}
	grpc_runtime.DefaultHTTPErrorHandler(ctx, mux, m, w, req, err)
}

func CustomMatcher(key string) (string, bool) {
	switch textproto.CanonicalMIMEHeaderKey(key) {
	case "X-Original-Request-Uri":
		return key, true
	default:
		return grpc_runtime.DefaultHeaderMatcher(key)
	}
}
