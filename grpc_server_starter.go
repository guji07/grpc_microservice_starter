package grpc_microservice_starter

import (
	"context"
	"log"
	"net"
	"net/http"

	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_runtime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	wb_metrics "github.com/happywbfriends/metrics/v1"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type GrpcServerStarter struct {
	GrpcServer   *grpc.Server
	serverConfig ServerOptionsConfig
}

func NewGrpcServerStarter(serverConfig ServerOptionsConfig, unaryInterceptors []grpc.UnaryServerInterceptor) *GrpcServerStarter {
	unaryInterceptors = append(unaryInterceptors,
		otelgrpc.UnaryServerInterceptor(),
		UnaryMetricsInterceptor(serverConfig.ServiceName, serverConfig.ServiceNamespace, serverConfig.MetricsBind, wb_metrics.NewHTTPServerMetrics()),
		UnaryValidationInterceptor(),
		grpc_recovery.UnaryServerInterceptor())
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			unaryInterceptors...,
		))
	return &GrpcServerStarter{
		GrpcServer:   grpcServer,
		serverConfig: serverConfig,
	}
}

func (g *GrpcServerStarter) ServeGrpcAndHttpGateway(ctx context.Context, registerServiceFunc func(ctx context.Context, mux *grpc_runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error)) error {
	mux := grpc_runtime.NewServeMux(
		grpc_runtime.WithRoutingErrorHandler(handleRoutingError),
	)
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	// Set up OTLP tracing (stdout for debug).
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(g.serverConfig.JaegerUrl)))
	if err != nil {
		return err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(g.serverConfig.ServiceName),
		)),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	defer func() { _ = exp.Shutdown(context.Background()) }()

	lis, err := net.Listen("tcp", g.serverConfig.GrpcBind)
	if err != nil {
		log.Fatalln("Failed to listen:", err)
	}

	err = registerServiceFunc(ctx, mux, g.serverConfig.GrpcBind, opts)
	if err != nil {
		return err
	}
	// Serve gRPC Server
	go func() {
		log.Fatal(g.GrpcServer.Serve(lis))
	}()

	// Start HTTP server (and proxy calls to gRPC server endpoint)
	log.Printf("started grpc server on %s\n", g.serverConfig.GrpcBind)
	log.Printf("started http gateway on %s\n", g.serverConfig.HttpBind)
	return http.ListenAndServe(g.serverConfig.HttpBind, mux)
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
