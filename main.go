package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ===== Request / Response payloads =====

type RetagRequest struct {
	Src    string `json:"src"`
	Dest   string `json:"dest"`
	DryRun bool   `json:"dry_run"`
	Login *struct {
		Registry string `json:"registry"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"login,omitempty"`
}

type RetagResponse struct {
	OK        bool            `json:"ok"`
	Message   string          `json:"message,omitempty"`
	Commands  []CommandResult `json:"commands,omitempty"`
	Elapsed   string          `json:"elapsed"`
	RequestID string          `json:"request_id"`
}

type CommandResult struct {
	Cmd    string `json:"cmd"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Code   int    `json:"code"`
}

// ===== main =====

func main() {
	addr := getenv("ADDR", ":8080")
	apiToken := os.Getenv("API_TOKEN")
	appID := getenv("APPS_ID", "retag")
	svcName := getenv("SERVICE_NAME", "retag-api")

	// JSON logger (stdout + file)
	logDir := getenv("LOG_DIR", "/var/log/retag-api")
	must(os.MkdirAll(logDir, 0o755))
	logPath := filepath.Join(logDir, "access.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	must(err)
	defer f.Close()
	jlog := log.New(io.MultiWriter(os.Stdout, f), "", 0)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	// POST /retag
	mux.Handle("/retag", authMiddleware(apiToken, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		defer r.Body.Close()

		var req RetagRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}
		if err := validateReq(req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()

		start := time.Now()
		results := []CommandResult{}

		// optional docker login
		if req.Login != nil && req.Login.Registry != "" && req.Login.Username != "" {
			if req.DryRun {
				results = append(results, CommandResult{Cmd: fmt.Sprintf("docker login %s -u %s -p ********", req.Login.Registry, req.Login.Username)})
			} else {
				cr := run(ctx, "docker", "login", req.Login.Registry, "-u", req.Login.Username, "-p", req.Login.Password)
				results = append(results, cr)
				if cr.Code != 0 {
					resp := RetagResponse{OK: false, Message: "docker login failed", Commands: results, Elapsed: time.Since(start).String(), RequestID: getReqID(r.Context())}
					writeJSON(w, http.StatusUnauthorized, resp); return
				}
			}
		} else if envHasLogin() {
			reg := getenv("DOCKER_REGISTRY", "")
			user := getenv("DOCKER_USERNAME", "")
			pass := getenv("DOCKER_PASSWORD", "")
			if reg != "" && user != "" {
				if req.DryRun {
					results = append(results, CommandResult{Cmd: fmt.Sprintf("docker login %s -u %s -p ********", reg, user)})
				} else {
					cr := run(ctx, "docker", "login", reg, "-u", user, "-p", pass)
					results = append(results, cr)
					if cr.Code != 0 {
						resp := RetagResponse{OK: false, Message: "docker login failed", Commands: results, Elapsed: time.Since(start).String(), RequestID: getReqID(r.Context())}
						writeJSON(w, http.StatusUnauthorized, resp); return
					}
				}
			}
		}

		// pull
		if req.DryRun {
			results = append(results, CommandResult{Cmd: fmt.Sprintf("docker pull %s", req.Src)})
		} else {
			results = append(results, run(ctx, "docker", "pull", req.Src))
			if results[len(results)-1].Code != 0 {
				resp := RetagResponse{OK: false, Message: "docker pull failed", Commands: results, Elapsed: time.Since(start).String(), RequestID: getReqID(r.Context())}
				writeJSON(w, http.StatusBadGateway, resp); return
			}
		}

		// tag
		if req.DryRun {
			results = append(results, CommandResult{Cmd: fmt.Sprintf("docker tag %s %s", req.Src, req.Dest)})
		} else {
			results = append(results, run(ctx, "docker", "tag", req.Src, req.Dest))
			if results[len(results)-1].Code != 0 {
				resp := RetagResponse{OK: false, Message: "docker tag failed", Commands: results, Elapsed: time.Since(start).String(), RequestID: getReqID(r.Context())}
				writeJSON(w, http.StatusBadGateway, resp); return
			}
		}

		// push
		if req.DryRun {
			results = append(results, CommandResult{Cmd: fmt.Sprintf("docker push %s", req.Dest)})
			resp := RetagResponse{OK: true, Message: "dry-run ok", Commands: results, Elapsed: time.Since(start).String(), RequestID: getReqID(r.Context())}
			writeJSON(w, http.StatusOK, resp); return
		}
		results = append(results, run(ctx, "docker", "push", req.Dest))
		if results[len(results)-1].Code != 0 {
			resp := RetagResponse{OK: false, Message: "docker push failed", Commands: results, Elapsed: time.Since(start).String(), RequestID: getReqID(r.Context())}
			writeJSON(w, http.StatusBadGateway, resp); return
		}

		resp := RetagResponse{OK: true, Message: "retag + push success", Commands: results, Elapsed: time.Since(start).String(), RequestID: getReqID(r.Context())}
		writeJSON(w, http.StatusOK, resp)
	})))

	// server with JSON logging + server-side RequestID
	handler := withServerRequestID(jsonLogMiddleware(jlog, appID, svcName, mux))

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

// ===== helpers =====

func validateReq(req RetagRequest) error {
	if strings.TrimSpace(req.Src) == "" || strings.TrimSpace(req.Dest) == "" {
		return errors.New("src and dest are required")
	}
	if !strings.Contains(req.Src, ":") {
		return errors.New("src must include a tag, e.g. my.registry/repo:tag")
	}
	if !strings.Contains(req.Dest, ":") {
		return errors.New("dest must include a tag, e.g. my.registry/repo:newtag")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envHasLogin() bool {
	return os.Getenv("DOCKER_USERNAME") != "" && os.Getenv("DOCKER_REGISTRY") != ""
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// ===== auth (inline) =====

func authMiddleware(apiToken string, next http.Handler) http.Handler {
	if apiToken == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		const pfx = "Bearer "
		if !strings.HasPrefix(h, pfx) || strings.TrimSpace(strings.TrimPrefix(h, pfx)) != apiToken {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(` + "`" + `{"error":"unauthorized"}` + "`" + `))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ===== JSON logging + RequestID =====

type reqIDKey struct{}

func withServerRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := genReqID()
		ctx := context.WithValue(r.Context(), reqIDKey{}, id)
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getReqID(ctx context.Context) string {
	if v := ctx.Value(reqIDKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

type respRecorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (rr *respRecorder) WriteHeader(code int) {
	rr.status = code
	rr.ResponseWriter.WriteHeader(code)
}
func (rr *respRecorder) Write(b []byte) (int, error) {
	rr.buf.Write(b)
	return rr.ResponseWriter.Write(b)
}

func jsonLogMiddleware(jlog *log.Logger, appID, svc string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		serverReqID := getReqID(r.Context())
		clientReqID := r.Header.Get("X-Request-Id")

		// read req body (limit 1MB)
		var reqBody any = nil
		if r.Body != nil {
			limited := io.LimitedReader{R: r.Body, N: 1 << 20}
			b, _ := io.ReadAll(&limited)
			r.Body = io.NopCloser(bytes.NewReader(b))
			if len(b) > 0 {
				var m any
				if json.Unmarshal(b, &m) == nil {
					maskJSON(m)
					reqBody = m
				} else {
					reqBody = string(b)
				}
			}
		}
		// headers (mask Authorization)
		hdr := map[string][]string{}
		for k, v := range r.Header {
			if strings.EqualFold(k, "Authorization") {
				hdr[k] = []string{"***"}
			} else {
				hdr[k] = v
			}
		}
		// request log
		reqLog := map[string]any{
			"Time":            nowJakarta(),
			"AppsID":          appID,
			"Service":         svc,
			"RequestID":       serverReqID,
			"ClientRequestID": clientReqID,
			"Method":          r.Method,
			"URI":             r.URL.Path,
			"Request":         reqBody,
			"Header":          hdr,
			"RemoteAddr":      r.RemoteAddr,
			"Event":           "request",
		}
		if b, err := json.Marshal(reqLog); err == nil { jlog.Println(string(b)) }

		// response capture
		rec := &respRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)

		elapsed := time.Since(start).Milliseconds()
		var respBody any = nil
		if rec.buf.Len() > 0 {
			if json.Unmarshal(rec.buf.Bytes(), &respBody) != nil {
				respBody = rec.buf.String()
			}
		}

		respLog := map[string]any{
			"Time":         nowJakarta(),
			"AppsID":       appID,
			"Service":      svc,
			"RequestID":    serverReqID,
			"Method":       r.Method,
			"URI":          r.URL.Path,
			"Status":       rec.status,
			"Response":     respBody,
			"ResponseTime": elapsed,
			"Event":        "response",
		}
		if b, err := json.Marshal(respLog); err == nil { jlog.Println(string(b)) }
	})
}

// ===== misc =====

func nowJakarta() string {
	loc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		loc = time.FixedZone("WIB", 7*3600)
	}
	return time.Now().In(loc).Format("2006-01-02 15:04:05.000")
}

func genReqID() string {
	const letters = "0123456789ABCDEFGHJKLMNPQRSTVWXYZ"
	b := make([]byte, 26)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func maskJSON(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			lk := strings.ToLower(k)
			if lk == "password" || lk == "token" || lk == "authorization" || strings.Contains(lk, "secret") {
				t[k] = "********"
				continue
			}
			maskJSON(vv)
		}
	case []any:
		for i := range t {
			maskJSON(t[i])
		}
	default:
	}
}

// run docker CLI
func run(ctx context.Context, name string, args ...string) CommandResult {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	cr := CommandResult{
		Cmd:    name + " " + strings.Join(args, " "),
		Stdout: string(out),
		Stderr: "",
		Code:   code,
	}
	if code != 0 {
		cr.Stderr = string(out)
	}
	return cr
}
