package interceptors

import (
	"context"
	"net/http"
	"time"

	"github.com/guji07/grpc_microservice_starter/http_mapping"
	wb_metrics "github.com/happywbfriends/metrics/v1"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"google.golang.org/grpc"
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

func (m *MetricsInterceptor) MetricsInterceptorFunc(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	m.wbMetrics.IncNbConnections()
	defer m.wbMetrics.DecNbConnections()
	start := time.Now()

	// Calls the handler
	m.logger.Info("metrics interceptor start time", zap.Time("start", start))
	h, err := handler(ctx, req)
	respStatus, ok := status.FromError(err)
	if !ok || respStatus.Code() != 0 {
		m.wbMetrics.IncNbRequest(info.FullMethod, http_mapping.GrpcToHTTPCodesMapping(respStatus.Code()), "")
		m.wbMetrics.ObserveRequestDuration(info.FullMethod, http_mapping.GrpcToHTTPCodesMapping(respStatus.Code()), "", time.Since(start))
	} else {
		m.wbMetrics.ObserveRequestDuration(info.FullMethod, http.StatusOK, "", time.Since(start))
		m.wbMetrics.IncNbRequest(info.FullMethod, http.StatusOK, "")
	}
	m.logger.Info("metrics interceptor end time", zap.Time("end", time.Now()))

	return h, err
}
