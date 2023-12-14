package grpc_microservice_starter

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	wb_metrics "github.com/happywbfriends/metrics/v1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MetricsInterceptor struct {
	serviceName string
	metrics     metrics
}

type metrics struct {
	totalRequests *prometheus.CounterVec
	serverMetrics wb_metrics.HTTPServerMetrics
}

func UnaryMetricsInterceptor(serviceName, namespace, port string, wbMetrics wb_metrics.HTTPServerMetrics) func(
	ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	totalRequests := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "nb_req",
			Help:      "Number of total requests.",
		},
		[]string{"status", "method"},
	)
	go func() {
		log.Printf("Metrics started on %s", port)
		if err := http.ListenAndServe(port, promhttp.Handler()); err != nil {
			log.Printf("listen metrics finished: %v", err.Error())
		}
	}()
	return (&MetricsInterceptor{
		serviceName: serviceName,
		metrics:     metrics{totalRequests: totalRequests, serverMetrics: wbMetrics},
	}).MetricsInterceptorFunc
}

type ValidatorInterceptor struct {
}

func UnaryValidationInterceptor() func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return (&ValidatorInterceptor{}).ValidatorInterceptorFunc
}

// TODO ValidateAll
// The validate interface prior to protoc-gen-validate v0.6.0.
type validatorLegacy interface {
	Validate() error
}

type validationErrorInterface interface {
	Field() string
	Reason() string
	Cause() error
	Key() bool
	ErrorName() string
}

func (v *ValidatorInterceptor) ValidatorInterceptorFunc(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	start := time.Now()
	log.Printf("ValidatorInterceptorFunc start time: %v", start)
	err := req.(validatorLegacy).Validate()
	if err != nil {
		switch v := err.(type) {
		case validationErrorInterface:
			return nil, ConstructStatusValidationError(v.ErrorName(), v.Reason(), v.Field())
		}
		return nil, StatusFromCodeMessageDetails(codes.InvalidArgument, "ValidatorInterceptorFunc", err.Error())
	}
	h, err := handler(ctx, req)
	log.Printf("ValidatorInterceptorFunc end time: %v", time.Now())
	return h, err
}

func (m *MetricsInterceptor) MetricsInterceptorFunc(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	m.metrics.serverMetrics.IncNbConnections()
	defer m.metrics.serverMetrics.IncNbConnections()
	start := time.Now()

	// Calls the handler
	log.Printf("metrics interceptor start time: %v", start)
	h, err := handler(ctx, req)
	respStatus, ok := status.FromError(err)
	if !ok || respStatus.Code() != 0 {
		m.metrics.serverMetrics.IncNbRequest(info.FullMethod, GrpcToHTTPCodesMapping(respStatus.Code()), 0)
		m.metrics.serverMetrics.ObserveRequestDuration(info.FullMethod, GrpcToHTTPCodesMapping(respStatus.Code()), 0, time.Since(start))
	} else {
		m.metrics.serverMetrics.ObserveRequestDuration(info.FullMethod, http.StatusOK, 0, time.Since(start))
		m.metrics.serverMetrics.IncNbRequest(info.FullMethod, http.StatusOK, 0)
	}
	log.Printf("metrics interceptor end time: %v", time.Now())

	return h, err
}

type KeycloakInterceptor struct {
}

func GrpcToHTTPCodesMapping(code codes.Code) int {
	switch code {
	case codes.InvalidArgument:
		return http.StatusBadRequest
	case codes.NotFound:
		return http.StatusNotFound
	case codes.Internal:
		return http.StatusInternalServerError
	case codes.AlreadyExists:
		return http.StatusBadRequest
	}
	return http.StatusOK
}

func ConstructStatusValidationError(msg, desc, field string) error {
	st := status.New(codes.InvalidArgument, msg)
	v := &errdetails.BadRequest_FieldViolation{
		Field:       field,
		Description: desc,
	}
	br := &errdetails.BadRequest{}
	br.FieldViolations = append(br.FieldViolations, v)
	st, err := st.WithDetails(br)
	if err != nil {
		// If this errored, it will always error
		// here, so better panic, so we can figure
		// out why than have this silently passing.
		panic(fmt.Sprintf("Unexpected error attaching metadata: %v", err))
	}
	return st.Err()
}

func StatusFromCodeMessageDetails(code codes.Code, message, details string) error {
	st := status.New(code, message)
	errorInfo := errdetails.ErrorInfo{}
	errorInfo.Reason = details
	st, _ = st.WithDetails(&errorInfo)
	return st.Err()
}
