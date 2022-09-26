package internal

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cavaliergopher/grab/v3"
	"github.com/dchest/uniuri"
	"github.com/owenthereal/upterm/utils"
	log "github.com/sirupsen/logrus"
)

type VscodeWeb struct {
	Cmd                 *exec.Cmd
	CodeServerPath      string
	Port                int32
	HTTPServer          *http.Server
	VscodeWebSocketFile string
	VscodeWebSocketConn net.Listener
	VscodeWebFront      string
	Logger              log.FieldLogger
}

func (vw VscodeWeb) Write(p []byte) (n int, err error) {
	vw.Logger.Info(string(p))
	return len(p), nil
}

func UntarGZ(tarball, target string) error {
	r, err := os.Open(tarball)
	if err != nil {
		return err
	}

	uncompressedStream, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer uncompressedStream.Close()

	tarReader := tar.NewReader(uncompressedStream)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		path := filepath.Join(target, header.Name)
		info := header.FileInfo()
		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}

		err = (func() error {
			file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(file, tarReader)
			if err != nil {
				return err
			}
			return nil
		})()
		if err != nil {
			return err
		}
	}
	return nil
}

func UnZip(zipfile, target string) error {
	archive, err := zip.OpenReader(zipfile)
	if err != nil {
		return err
	}
	defer archive.Close()

	for _, f := range archive.File {
		filePath := filepath.Join(target, f.Name)

		if !strings.HasPrefix(filePath, filepath.Clean(target)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path: %s", filePath)
		}
		if f.FileInfo().IsDir() {
			if err = os.MkdirAll(filePath, os.ModePerm); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			return err
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		fileInArchive, err := f.Open()
		if err != nil {
			return err
		}

		if _, err := io.Copy(dstFile, fileInArchive); err != nil {
			return err
		}

		dstFile.Close()
		fileInArchive.Close()
	}
	return nil
}

func getCodeServer() (string, string, string) {
	keys := [][]string{
		// OS, ARCH, URL, zip, dir
		{"linux", "amd64", "server-linux-x64-web", "tar.gz", "vscode-server-linux-x64-web"},
		{"darwin", "amd64", "server-darwin-web", "zip", "vscode-server-darwin-x64-web"},
		{"darwin", "arm64", "server-darwin-arm64-web", "zip", "vscode-server-darwin-arm64-web"},
		// {"windows", "amd64", "server-win32-x64-web", "zip", "vscode-server-win32-x64-web"},
	}
	for _, k := range keys {
		if k[0] == runtime.GOOS && k[1] == runtime.GOARCH {
			return k[2], k[3], k[4]
		}
	}
	fmt.Printf("We can't support your OS/ARCH: %s/%s", runtime.GOOS, runtime.GOARCH)
	return "", "", ""
}

func Download(dst, url string) (bool, string, error) {
	req, nil := grab.NewRequest(dst, url)
	fmt.Printf("Downloading %v...\n", req.URL())
	client := grab.NewClient()
	resp := client.Do(req)
	isChange := false
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
Loop:
	for {
		select {
		case <-t.C:
			isChange = true
			fmt.Printf("  transferred %v / %v bytes (%.2f%%)\n",
				resp.BytesComplete(), resp.Size(), 100*resp.Progress())
		case <-resp.Done:
			// download is complete
			break Loop
		}
	}

	// check for errors
	if err := resp.Err(); err != nil {
		return false, "", err
	}
	return isChange, resp.Filename, nil
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}
type vscodeProduct struct {
	Quality string `json:"quality"`
	Commit  string `json:"commit"`
}

// Use the Writer part of gzipResponseWriter to write the output.

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func (vw *VscodeWeb) PrepareVSCodeWeb() error {
	txt, postfix, dirBase := getCodeServer()
	uptermDir, err := utils.UptermDir()
	if err != nil {
		return err
	}
	downloadURL := fmt.Sprintf("https://update.code.visualstudio.com/latest/%s/stable", txt)
	isChange, dst, err := Download(uptermDir, downloadURL)
	if err != nil {
		vw.Logger.Errorf("download %s failed: %v\n", dst, err)
		return err
	}

	codeBase := filepath.Join(uptermDir, dirBase)
	_, err = os.Stat(codeBase)
	if isChange || errors.Is(err, fs.ErrNotExist) { // file changed
		fmt.Printf("Decompress to %v...\n", codeBase)
		filepath.Clean(codeBase)
		if postfix == "zip" {
			if err := UnZip(dst, uptermDir); err != nil {
				vw.Logger.Errorf("unzip %s failed: %v\n", dst, err)
				return err
			}
		} else if postfix == "tar.gz" {
			if err := UntarGZ(dst, uptermDir); err != nil {
				vw.Logger.Errorf("untar %s failed: %v\n", dst, err)
				return err
			}
		}
	}

	vw.CodeServerPath = filepath.Join(codeBase, "bin", "code-server")
	vw.VscodeWebSocketFile = filepath.Join(uptermDir, fmt.Sprintf("%s-vscode-web.sock", uniuri.NewLen(24)))

	// reverse proxy for .upterm route
	uptermFrontUrl, err := url.Parse(vw.VscodeWebFront)
	if err != nil {
		return err
	}
	loadingProxy := httputil.NewSingleHostReverseProxy(uptermFrontUrl)

	// unix socket proxy
	mux := http.NewServeMux()
	remote, err := url.Parse("http://localhost")
	if err != nil {
		return err
	}

	// reverse proxy for static file
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.Transport = &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			// a fake server by unixsocket
			// From: https://stackoverflow.com/a/26224019/5563477
			return net.Dial("unix", vw.VscodeWebSocketFile)
		},
	}
	vscodeHandler := func(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("upterm") == "true" {
				loadingProxy.ServeHTTP(w, r)
			} else {
				p.ServeHTTP(w, r)
			}
		}
	}
	corsMiddleware := func(fs http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS,PUT")
			w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type")
			if r.Method == "OPTIONS" {
				return
			}
			fs.ServeHTTP(w, r)
		}
	}
	makeGzipHandler := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Check if the client can accept the gzip encoding.
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				// The client cannot accept it, so return the output
				// uncompressed.
				fn(w, r)
				return
			}
			// Set the HTTP header indicating encoding.
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			defer gz.Close()
			fn(gzipResponseWriter{Writer: gz, ResponseWriter: w}, r)
		}
	}
	staticRoute, err := (func() (string, error) {
		// Please refer to:
		// https://github.com/microsoft/vscode/commit/41f49066bde4af7f70aa4d5d06816660074612f8
		// src/vs/server/node/webClientServer.ts
		jsonFile, err := os.Open(filepath.Join(codeBase, "product.json"))
		if err != nil {
			return "", err
		}
		defer jsonFile.Close()
		var product vscodeProduct
		byteValue, _ := io.ReadAll(jsonFile)
		err = json.Unmarshal([]byte(byteValue), &product)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("/%s-%s/static/", product.Quality, product.Commit), nil
	}())

	if err != nil {
		return err
	}
	mux.Handle(staticRoute, http.StripPrefix(staticRoute, makeGzipHandler(corsMiddleware(http.FileServer(http.Dir(codeBase))))))
	mux.Handle("/static/", http.StripPrefix("/static/", makeGzipHandler(corsMiddleware(http.FileServer(http.Dir(codeBase))))))

	mux.Handle("/.upterm/", loadingProxy)

	// real server
	mux.HandleFunc("/", vscodeHandler(proxy))

	port := 0
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	vw.Port = int32(ln.Addr().(*net.TCPAddr).Port)
	vw.HTTPServer = &http.Server{Handler: mux}
	go func() {
		if err = vw.HTTPServer.Serve(ln); err != nil {
			vw.Logger.Error("create vscode web error", err)
		}
	}()

	return nil
}

func (vw *VscodeWeb) Run(ctx context.Context) error {
	vw.Cmd = exec.Command(
		vw.CodeServerPath,
		"--without-connection-token",
		"--accept-server-license-terms",
		"--socket-path", vw.VscodeWebSocketFile,
	)
	vw.Cmd.Stdout = vw
	vw.Cmd.Stderr = vw

	vw.Logger.Info("Starting vscode-web...")
	if err := vw.Cmd.Start(); err != nil {
		vw.Logger.Errorf("Failed to start cmd: %v", err)
		return err
	}
	if err := vw.Cmd.Wait(); err != nil {
		return err
	}
	return nil
}

func (vw *VscodeWeb) Stop() {
	defer os.Remove(vw.VscodeWebSocketFile)
	defer vw.HTTPServer.Close()
	vw.Logger.Info("Stop vscode-web...")
	if vw.Cmd != nil {
		if err := vw.Cmd.Process.Signal(syscall.SIGTERM); err != nil {
			vw.Logger.Errorf("Failed to stop vscode web cmd: %v", err)
		}
	}
}
