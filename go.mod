module github.com/jingweno/upterm

go 1.13

require (
	github.com/ScaleFT/sshkeys v0.0.0-20181112160850-82451a803681
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20161002113705-648efa622239 // indirect
	github.com/creack/pty v1.1.9
	github.com/dchest/bcrypt_pbkdf v0.0.0-20150205184540-83f37f9c154a // indirect
	github.com/eiannone/keyboard v0.0.0-20190314115158-7169d0afeb4f
	github.com/flynn/go-shlex v0.0.0-20150515145356-3f9db97f8568 // indirect
	github.com/gliderlabs/ssh v0.2.2
	github.com/go-kit/kit v0.9.0
	github.com/go-openapi/errors v0.19.2
	github.com/go-openapi/runtime v0.19.5
	github.com/go-openapi/strfmt v0.19.3
	github.com/go-openapi/swag v0.19.5
	github.com/golang/protobuf v1.3.2
	github.com/google/go-cmp v0.3.1
	github.com/google/shlex v0.0.0-20181106134648-c34317bd91bf
	github.com/gorilla/websocket v1.4.1
	github.com/grpc-ecosystem/grpc-gateway v1.12.1
	github.com/heroku/rollrus v0.1.1
	github.com/influxdata/influxdb1-client v0.0.0-20191209144304-8bf82d3c094d // indirect
	github.com/oklog/run v1.0.0
	github.com/olekukonko/tablewriter v0.0.4
	github.com/pborman/ansi v0.0.0-20160920233902-86f499584b0a
	github.com/prometheus/client_golang v1.3.0
	github.com/rollbar/rollbar-go v1.2.0 // indirect
	github.com/rs/xid v1.2.1
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.0.0-20191029031824-8986dd9e96cf
	golang.org/x/net v0.0.0-20191209160850-c0dbc17a3553 // indirect
	golang.org/x/sys v0.0.0-20200117145432-59e60aa80a0c // indirect
	google.golang.org/genproto v0.0.0-20191206224255-0243a4be9c8f
	google.golang.org/grpc v1.25.1
	gopkg.in/yaml.v2 v2.2.7 // indirect
)

replace (
	github.com/gliderlabs/ssh => github.com/jingweno/ssh v0.2.3-0.20191221201824-4cd54473e34e
	golang.org/x/crypto => github.com/jingweno/upterm.crypto v0.0.0-20200126213837-9c017ed1a05e
)
