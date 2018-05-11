package log

import (
	"log"
	"os"
)

const DEBUG_LEVEL, INFO_LEVEL, WARNING_LEVEL, ERROR_LEVEL = 3, 5, 7, 9

const DEFAULT_LEVEL = DEBUG_LEVEL

// debug,info,waring,error prefix
const DEBUG_PREFIX, INFO_PREFIX, WARNING_PREFIX, ERROR_PREFIX = "DEBUG ", "INFO ", "WARNING ", "ERROR "

// 默认的 输出流
var default_out, default_err_out = os.Stdout, os.Stderr

type LLogger struct {
	debugl   *log.Logger
	infol    *log.Logger
	warningl *log.Logger
	errorl   *log.Logger

	level int
}

// new
// 参照 log.logger 实现
func NewStd(prefix string, flag int, level int) *LLogger {
	var debugl = log.New(os.Stdout, prefix+DEBUG_PREFIX, flag)
	var infol = log.New(os.Stdout, prefix+INFO_PREFIX, flag)
	var warningl = log.New(os.Stderr, prefix+WARNING_PREFIX, flag)
	var errorl = log.New(os.Stderr, prefix+ERROR_PREFIX, flag)

	return &LLogger{debugl: debugl, infol: infol, warningl: warningl, errorl: errorl, level: level}
}

var std = NewStd("", log.LstdFlags, DEFAULT_LEVEL)

func (logger *LLogger) Debugf(format string, v ...interface{}) {
	if DEBUG_LEVEL >= logger.level {
		logger.debugl.Printf(format, v...)
	}
}

func (logger *LLogger) Infof(format string, v ...interface{}) {
	if INFO_LEVEL >= logger.level {
		logger.infol.Printf(format, v...)
	}
}

func (logger *LLogger) Warningf(format string, v ...interface{}) {
	if WARNING_LEVEL >= logger.level {
		logger.warningl.Printf(format, v...)
	}
}

func (logger *LLogger) Errorf(format string, v ...interface{}) {
	if ERROR_LEVEL >= logger.level {
		logger.errorl.Printf(format, v...)
	}
}

// 默认调用 panic 的情况是出现了必须终止的错误
func (logger *LLogger) Panicf(format string, v ...interface{}) {
	logger.errorl.Panicf(format, v...)
}

func Debugf(format string, v ...interface{}) {
	if DEBUG_LEVEL >= std.level {
		std.debugl.Printf(format, v...)
	}
}

func Debugfln(format string, v ...interface{}) {
	if DEBUG_LEVEL >= std.level {
		std.debugl.Printf(format, v...)
	}
}

func Infof(format string, v ...interface{}) {
	if INFO_LEVEL >= std.level {
		std.infol.Printf(format, v...)
	}
}

func Infofln(format string, v ...interface{}) {
	if INFO_LEVEL >= std.level {
		std.infol.Printf(format+"\n", v...)
	}
}

func Warningf(format string, v ...interface{}) {
	if WARNING_LEVEL >= std.level {
		std.warningl.Printf(format, v...)
	}
}

func Errorf(format string, v ...interface{}) {
	if ERROR_LEVEL >= std.level {
		std.errorl.Printf(format, v...)
	}
}

func Errorfln(format string, v ...interface{}) {
	if ERROR_LEVEL >= std.level {
		std.errorl.Printf(format+"\n", v...)
	}
}

// 默认调用 panic 的情况是出现了必须终止的错误
func Panicf(format string, v ...interface{}) {
	std.errorl.Panicf(format, v...)
}
