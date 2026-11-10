package logger

import (
	"context"
	"log/slog"

	"go.temporal.io/proxy/pkg/logger/tag"
)

// slogHandler adapts a [Logger] to [slog.Handler], for libraries that log
// through slog. Attribute values are rendered as strings.
type slogHandler struct {
	l      Logger
	prefix string
}

// NewSlogHandler returns a [slog.Handler] that writes to l.
func NewSlogHandler(l Logger) slog.Handler {
	return &slogHandler{l: l}
}

func (h *slogHandler) Enabled(_ context.Context, lvl slog.Level) bool {
	return h.l.Enabled(levelOf(lvl))
}

func (h *slogHandler) Handle(_ context.Context, r slog.Record) error {
	tags := make([]tag.Tag, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		tags = append(tags, h.tags(h.prefix, a)...)
		return true
	})

	switch levelOf(r.Level) {
	case LevelDebug:
		h.l.Debug(r.Message, tags...)
	case LevelInfo:
		h.l.Info(r.Message, tags...)
	case LevelWarn:
		h.l.Warn(r.Message, tags...)
	default:
		h.l.Error(r.Message, tags...)
	}

	return nil
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var tags []tag.Tag
	for _, a := range attrs {
		tags = append(tags, h.tags(h.prefix, a)...)
	}

	return &slogHandler{l: h.l.With(tags...), prefix: h.prefix}
}

func (h *slogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}

	return &slogHandler{l: h.l, prefix: h.prefix + name + "."}
}

func (h *slogHandler) tags(prefix string, a slog.Attr) []tag.Tag {
	v := a.Value.Resolve()
	if v.Kind() != slog.KindGroup {
		return []tag.Tag{tag.String(prefix+a.Key, v.String())}
	}

	var tags []tag.Tag
	for _, ga := range v.Group() {
		tags = append(tags, h.tags(prefix+a.Key+".", ga)...)
	}

	return tags
}

func levelOf(l slog.Level) Level {
	switch {
	case l < slog.LevelInfo:
		return LevelDebug
	case l < slog.LevelWarn:
		return LevelInfo
	case l < slog.LevelError:
		return LevelWarn
	default:
		return LevelError
	}
}
