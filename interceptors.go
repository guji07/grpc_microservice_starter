package grpc_microservice_starter

import (
	"context"
	"fmt"
	"go.uber.org/zap"
	"net/http"
	"time"

	wb_metrics "github.com/happywbfriends/metrics/v1"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MetricsInterceptor struct {
	wbMetrics wb_metrics.HTTPServerMetrics
	logger    *zap.Logger
}

func UnaryMetricsInterceptor(port string, wbMetrics wb_metrics.HTTPServerMetrics, logger *zap.Logger) func(
	ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	go func() {
		logger.Info("Metrics started", zap.String("port", port))
		if err := http.ListenAndServe(port, promhttp.Handler()); err != nil {
			logger.Error("listen metrics finished", zap.Error(err))
		}
	}()
	return (&MetricsInterceptor{
		wbMetrics: wbMetrics,
		logger:    logger,
	}).MetricsInterceptorFunc
}

type ValidatorInterceptor struct {
	logger *zap.Logger
}

func ValidationUnaryInterceptor(logger *zap.Logger) func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return (&ValidatorInterceptor{logger: logger}).ValidatorInterceptorFunc
}

type validator interface {
	Validate(all bool) error
}

type validationErrorInterface interface {
	Field() string
	Reason() string
	Cause() error
	Key() bool
	ErrorName() string
}

type validationMultiErrorInterface interface {
	AllErrors() []error
}

func (v *ValidatorInterceptor) ValidatorInterceptorFunc(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	start := time.Now()
	v.logger.Info("ValidatorInterceptorFunc start time", zap.Time("start", start))
	err := req.(validator).Validate(true)
	if err != nil {
		switch v := err.(type) {
		case validationErrorInterface:
			return nil, ConstructStatusValidationError(v.ErrorName(), v.Reason(), v.Field())
		case validationMultiErrorInterface:
			return nil, nil
		}
		return nil, StatusFromCodeMessageDetails(codes.InvalidArgument, "ValidatorInterceptorFunc", err.Error())
	}
	h, err := handler(ctx, req)
	v.logger.Info("ValidatorInterceptorFunc end time", zap.Time("end", time.Now()))
	return h, err
}

func (m *MetricsInterceptor) MetricsInterceptorFunc(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	m.wbMetrics.IncNbConnections()
	defer m.wbMetrics.IncNbConnections()
	start := time.Now()

	// Calls the handler
	m.logger.Info("metrics interceptor start time", zap.Time("start", start))
	h, err := handler(ctx, req)
	respStatus, ok := status.FromError(err)
	if !ok || respStatus.Code() != 0 {
		m.wbMetrics.IncNbRequest(info.FullMethod, GrpcToHTTPCodesMapping(respStatus.Code()), 0)
		m.wbMetrics.ObserveRequestDuration(info.FullMethod, GrpcToHTTPCodesMapping(respStatus.Code()), 0, time.Since(start))
	} else {
		m.wbMetrics.ObserveRequestDuration(info.FullMethod, http.StatusOK, 0, time.Since(start))
		m.wbMetrics.IncNbRequest(info.FullMethod, http.StatusOK, 0)
	}
	m.logger.Info("metrics interceptor end time", zap.Time("end", time.Now()))

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
