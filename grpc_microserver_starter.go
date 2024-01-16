package grpc_microservice_starter

import (
	"context"
	"net"
	"net/http"

	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_runtime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/guji07/grpc_microservice_starter/interceptors"
	"github.com/guji07/grpc_microservice_starter/interceptors/keycloak"
	grpc_microservice_starter "github.com/guji07/grpc_microservice_starter/proto"
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
	GrpcServer     *grpc.Server
	config         Config
	jaegerExporter jaeger.Exporter
	logger         *zap.Logger
}

// NewGrpcServerStarter - main function of library
// to use library:
// create new GrpcServerStarter with Config
// register your YourController with proto.RegisterYourServiceServer(GrpcServerStarter, YourController), where proto -
//
//	name of the package with generated code
//
// start if err := GrpcServerStarter.Start(ctx, proto.RegisterYourServiceHandlerFromEndpoint); err != nil { serverStarter.Stop(ctx) }
func NewGrpcServerStarter(config Config, unaryInterceptors []grpc.UnaryServerInterceptor) *GrpcServerStarter {
	logger, _ := zap.NewProduction()
	metricsUnaryInterceptor := interceptors.UnaryMetricsInterceptor(config.Server.MetricsBind, wb_metrics.NewHTTPServerMetrics(), logger)
	service, err := keycloak.NewService(context.Background(), &config.Keycloak, logger)
	if err != nil {
		logger.Fatal("can't get keycloak service", zap.Error(err))
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			initUnaryInterceptors(unaryInterceptors, config.Interceptor, metricsUnaryInterceptor, service, logger)...,
		),
		grpc.ChainStreamInterceptor(
			grpc_recovery.StreamServerInterceptor(),
			otelgrpc.StreamServerInterceptor()),
	)

	return &GrpcServerStarter{
		GrpcServer: grpcServer,
		config:     config,
		logger:     logger,
	}
}

func initUnaryInterceptors(unaryInterceptors []grpc.UnaryServerInterceptor,
	interceptorConfig InterceptorConfig,
	metricsUnaryInterceptor func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error),
	service *keycloak.Service,
	logger *zap.Logger) []grpc.UnaryServerInterceptor {

	if interceptorConfig.EnableKeycloakInterceptor {
		unaryInterceptors = append(unaryInterceptors, keycloak.NewInterceptor(service, interceptorConfig.EscapePrefix).KeycloakInterceptorFunc)
	}
	if interceptorConfig.EnableValidationInterceptor {
		unaryInterceptors = append(unaryInterceptors, interceptors.ValidationUnaryInterceptor(logger))
	}
	if interceptorConfig.EnableMetricsInterceptor {
		unaryInterceptors = append(unaryInterceptors, metricsUnaryInterceptor)
	}
	unaryInterceptors = append(unaryInterceptors,
		//TODO Deprecated: Use [NewServerHandler] instead.
		otelgrpc.UnaryServerInterceptor(),
		grpc_recovery.UnaryServerInterceptor())
	return unaryInterceptors
}

func (g *GrpcServerStarter) Start(ctx context.Context, registerServiceFunc func(ctx context.Context, mux *grpc_runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error)) error {
	// Set up OTLP tracing (stdout for debug).
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(g.config.JaegerUrl)))
	if err != nil {
		return err
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
	defer func() { _ = exp.Shutdown(context.Background()) }()

	lis, err := net.Listen("tcp", g.config.Server.GrpcBind)
	if err != nil {
		g.logger.Fatal("Failed to listen:", zap.Error(err))
	}
	mux := grpc_runtime.NewServeMux(
		grpc_runtime.WithMetadata(func(_ context.Context, req *http.Request) metadata.MD {
			return metadata.New(map[string]string{
				keycloak.ParamName_State:        req.URL.Query().Get(keycloak.ParamName_State),
				keycloak.ParamName_Code:         req.URL.Query().Get(keycloak.ParamName_Code),
				keycloak.ParamName_SessionState: req.URL.Query().Get(keycloak.ParamName_SessionState),
				keycloak.ParamName_BackURL:      req.URL.Query().Get(keycloak.ParamName_BackURL),
				"RequestURI":                    req.URL.RequestURI(),
			})
		}),
		grpc_runtime.WithRoutingErrorHandler(handleRoutingError),
		//custom error handling - for example when no token to keycloak we return json with redirect_url
		grpc_runtime.WithErrorHandler(g.httpErrorHandlerFunc),
		grpc_runtime.WithIncomingHeaderMatcher(CustomMatcher),
	)
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	err = registerServiceFunc(ctx, mux, g.config.Server.GrpcBind, opts)
	if err != nil {
		return err
	}

	// Serve probes
	go func() {
		g.logger.Info("started probes on", zap.String("bind", g.config.Server.ProbeBind))
		startProbes(g.config, g.logger)
	}()
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

func (g *GrpcServerStarter) Stop(ctx context.Context) {
	err := g.jaegerExporter.Shutdown(ctx)
	if err != nil {
		g.logger.Warn("jaeger shutdown error", zap.Error(err))
		return
	}
}

func startProbes(cfg Config, logger *zap.Logger) {
	if cfg.Server.ProbeBind == "" {
		logger.Error("Probes not started because bind parameter is empty")
		return
	}

	http.HandleFunc("/alive", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("ok"))
		if err != nil {
			logger.Error("error responding to probe", zap.Error(err))
		}
	})
	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("ok"))
		if err != nil {
			logger.Error("error responding to probe", zap.Error(err))
		}
	})
	go func() {
		if err := http.ListenAndServe(cfg.Server.ProbeBind, nil); err != nil {
			logger.Error("listen probe failed", zap.Error(err))
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
		// TODO:
		//md, ok := runtime.ServerMetadataFromContext(ctx)
		//	if !ok {
		//		return nil
		//	}
		//  if vals := md.HeaderMD.Get("x-http-code"); len(vals) > 0 {
		//		code, err := strconv.Atoi(vals[0])
		//		switch code {
		//		401: {
		//			httpStatusError := grpc_runtime.HTTPStatusError{
		//				HTTPStatus: http.StatusUnauthorized,
		//				Err:        err,
		//			}
		//			w.Header().Set("Content-Type", "application/json")
		//			w.WriteHeader(httpStatusError.HTTPStatus)
		//			protoRedirect := (s.Details()[0]).(*grpc_microservice_starter.RedirectResponse)
		//			protoRedirect.Cookies = nil
		//			msg, _ := protojson.Marshal(protoRedirect)
		//			_, err := w.Write(msg)
		//			if err != nil {
		//				g.logger.Fatal("error writing custom http response", zap.Error(err))
		//			}
		//			return
		//}
		//
		//		307: write cookies + http.Redirect(w, req, protoRedirect.RedirectUrl, http.StatusTemporaryRedirect)
		//	if err != nil {
		//		return err
		//	}
		//	delete(md.HeaderMD, "x-http-code")
		//	delete(w.Header(), "Grpc-Metadata-X-Http-Code")
		//	w.WriteHeader(code)
		//}
		if s.Code() == codes.Unauthenticated {
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
		} else if s.Code() == 307 {
			protoRedirect := (s.Details()[0]).(*grpc_microservice_starter.RedirectResponse)
			for _, v := range protoRedirect.Cookies {
				w.Header().Add("Set-Cookie", v)
			}
			http.Redirect(w, req, protoRedirect.RedirectUrl, http.StatusTemporaryRedirect)
		}
		//if we don't have handling for this code than fall to grpc_runtime.DefaultHTTPErrorHandler(ctx, mux, m, w, req, err)
	}
	//default way of handling error
	grpc_runtime.DefaultHTTPErrorHandler(ctx, mux, m, w, req, err)
}

func CustomMatcher(key string) (string, bool) {
	switch key {
	case "X-Original-Request-Uri":
		return key, true
	default:
		return grpc_runtime.DefaultHeaderMatcher(key)
	}
}
