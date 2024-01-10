package grpc_microservice_starter

import (
	"context"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_runtime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/guji07/grpc_microservice_starter/interceptors"
	"github.com/guji07/grpc_microservice_starter/interceptors/keycloak"
	wb_metrics "github.com/happywbfriends/metrics/v1"
	"net"
	"net/http"

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
	"google.golang.org/grpc/status"
)

type GrpcServerStarter struct {
	GrpcServer     *grpc.Server
	config         Config
	jaegerExporter jaeger.Exporter
	logger         *zap.Logger
}

func NewGrpcServerStarter(serverConfig Config, keycloakConfig keycloak.Config, unaryInterceptors []grpc.UnaryServerInterceptor) *GrpcServerStarter {
	logger, _ := zap.NewProduction()
	metricsUnaryInterceptor := interceptors.UnaryMetricsInterceptor(serverConfig.MetricsBind, wb_metrics.NewHTTPServerMetrics(), logger)
	service, err := keycloak.NewService(context.Background(), &keycloakConfig, logger)
	if err != nil {
		logger.Fatal("can't get keycloak service", zap.Error(err))
	}
	unaryInterceptors = append(unaryInterceptors,
		//TODO Deprecated: Use [NewServerHandler] instead.
		otelgrpc.UnaryServerInterceptor(),
		keycloak.NewInterceptor(service).KeycloakInterceptorFunc,
		metricsUnaryInterceptor,
		interceptors.ValidationUnaryInterceptor(logger),
		grpc_recovery.UnaryServerInterceptor())

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			unaryInterceptors...,
		),
		grpc.ChainStreamInterceptor(
			grpc_recovery.StreamServerInterceptor(),
			otelgrpc.StreamServerInterceptor()),
	)

	return &GrpcServerStarter{
		GrpcServer: grpcServer,
		config:     serverConfig,
		logger:     logger,
	}
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

	lis, err := net.Listen("tcp", g.config.GrpcBind)
	if err != nil {
		g.logger.Fatal("Failed to listen:", zap.Error(err))
	}
	mux := grpc_runtime.NewServeMux(
		grpc_runtime.WithRoutingErrorHandler(handleRoutingError),
	)
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	err = registerServiceFunc(ctx, mux, g.config.GrpcBind, opts)
	if err != nil {
		return err
	}

	// Serve probes
	go func() {
		g.logger.Info("started probes on", zap.String("bind", g.config.ProbeBind))
		startProbes(g.config, g.logger)
	}()
	// Serve gRPC Server
	go func() {
		g.logger.Info("started grpc server on", zap.String("bind", g.config.GrpcBind))
		err = g.GrpcServer.Serve(lis)
		if err != nil {
			g.logger.Fatal("grpc server finished", zap.Error(err))
		}
	}()

	g.logger.Info("started http gateway on", zap.String("bind", g.config.HttpBind))
	err = http.ListenAndServe(g.config.HttpBind, mux)
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
	if cfg.ProbeBind == "" {
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
		logger.Info("Probe started on", zap.String("bind", cfg.ProbeBind))
		if err := http.ListenAndServe(cfg.ProbeBind, nil); err != nil {
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
