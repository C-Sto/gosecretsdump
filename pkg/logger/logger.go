package logger

import (
	"go.uber.org/zap"
)

var Logger *zap.Logger

func init() {
	lc := zap.NewDevelopmentConfig()
	lc.EncoderConfig.TimeKey = ""
	Logger, _ = lc.Build()

}
