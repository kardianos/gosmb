// Package smblog provides logging with areas and verbosity control for SMB components.
package smblog

import (
	"fmt"
	"io"
	"os"
	"time"
)

// Area identifies different logging areas for filtering.
type Area int

const (
	AreaGeneral Area = iota
	AreaNetlink
	AreaRPC
	AreaAuth
	AreaShare
	AreaTree
)

// Logger provides logging with areas and verbosity control.
type Logger struct {
	output    io.Writer
	enabled   bool
	verbosity int           // 0=errors only, 1=info, 2=debug, 3=trace
	areas     map[Area]bool // nil means all areas enabled
}

// New creates a new logger. If output is nil, logging is disabled.
func New(output io.Writer) *Logger {
	return &Logger{
		output:    output,
		enabled:   output != nil,
		verbosity: 1,
		areas:     nil, // all areas enabled by default
	}
}

// SetVerbosity sets the verbosity level (0-3).
func (l *Logger) SetVerbosity(level int) {
	l.verbosity = level
}

// EnableArea enables logging for a specific area.
func (l *Logger) EnableArea(area Area) {
	if l.areas == nil {
		l.areas = make(map[Area]bool)
	}
	l.areas[area] = true
}

// DisableArea disables logging for a specific area.
func (l *Logger) DisableArea(area Area) {
	if l.areas == nil {
		return
	}
	delete(l.areas, area)
}

func (l *Logger) shouldLog(area Area, level int) bool {
	if !l.enabled || l.output == nil {
		return false
	}
	if level > l.verbosity {
		return false
	}
	if l.areas != nil && !l.areas[area] {
		return false
	}
	return true
}

func (l *Logger) log(area Area, level int, format string, args ...any) {
	if !l.shouldLog(area, level) {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.output, "%s %s\n", time.Now().Format("2006/01/02 15:04:05"), msg)
}

// Printf logs a general message at info level.
func (l *Logger) Printf(area Area, format string, args ...any) {
	l.log(area, 1, format, args...)
}

// Debugf logs a debug message.
func (l *Logger) Debugf(area Area, format string, args ...any) {
	l.log(area, 2, format, args...)
}

// Tracef logs a trace message (most verbose).
func (l *Logger) Tracef(area Area, format string, args ...any) {
	l.log(area, 3, format, args...)
}

// Fatalf logs and exits.
func (l *Logger) Fatalf(format string, args ...any) {
	if l.output != nil {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(l.output, "%s FATAL: %s\n", time.Now().Format("2006/01/02 15:04:05"), msg)
	}
	os.Exit(1)
}
