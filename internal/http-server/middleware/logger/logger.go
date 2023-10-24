package logger

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

func New(log *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		log = log.With(
			slog.String("component", "middleware/logger"),
		)

		log.Info("logger initialized")

		fn := func(w http.ResponseWriter, r *http.Request) {
			entry := log.With(
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("remote_addr", r.RemoteAddr),
				slog.String("user_agent", r.UserAgent()),
				slog.String("request_id", middleware.GetReqID(r.Context())),
			)
			entry.Info("request started")

			// создаёи обёртку вокруг `http.ResponseWriter`
			// ЧТобы получить сведения об ответе
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			// время получения запроса
			t1 := time.Now()

			// отправляем запись в лог после обработки запроса
			defer func() {
				entry.Info("request completed",
					slog.Int("content_lenth", ww.BytesWritten()),
					slog.Int("response_status", ww.Status()),
					slog.String("duration", time.Since(t1).String()),
				)
			}()

			// Передаём управление следующему обработчику
			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}
