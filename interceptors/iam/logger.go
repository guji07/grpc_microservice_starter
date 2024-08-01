package iam

import (
	"go.uber.org/zap"
)

type Logger struct {
	logger *zap.Logger
}

func NewLogger(logger *zap.Logger) *Logger {
	return &Logger{logger: logger}
}

func (l Logger) Debugf(f string, v ...interface{}) {
	l.logger.Debug(f, zap.Any("details", v))
}

func (l Logger) Infof(f string, v ...interface{}) {
	l.logger.Info(f, zap.Any("details", v))
}

func (l Logger) Warningf(f string, v ...interface{}) {
	l.logger.Warn(f, zap.Any("details", v))
}

func (l Logger) Errorf(f string, v ...interface{}) {
	l.logger.Error(f, zap.Any("details", v))
}
