package interceptors

import (
	"context"
	"github.com/guji07/grpc_microservice_starter/http_mapping"
	"time"

	"go.uber.org/zap"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

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
	switch req.(type) {
	case validator:
		err := req.(validator).Validate(true)
		if err != nil {
			switch v := err.(type) {
			case validationErrorInterface:
				return nil, http_mapping.ConstructStatusValidationError(v.ErrorName(), v.Reason(), v.Field())
			case validationMultiErrorInterface:
				return nil, nil
			}
			return nil, http_mapping.StatusFromCodeMessageDetails(codes.InvalidArgument, "ValidatorInterceptorFunc", err.Error())
		}
	}
	h, err := handler(ctx, req)
	v.logger.Info("ValidatorInterceptorFunc end time", zap.Time("end", time.Now()))
	return h, err
}
