// +heroku goVersion 1.21
// +heroku install ./cmd/uptermd/...

module github.com/owenthereal/upterm

go 1.21

require (
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/apex/log v1.9.0 // indirect
	github.com/bradfitz/iter v0.0.0-20191230175014-e8f45d346db8 // indirect
	github.com/buger/goterm v0.0.0-20200322175922-2f3e71b85129 // indirect
	github.com/c4milo/unpackit v0.0.0-20170704181138-4ed373e9ef1c // indirect
	github.com/creack/pty v1.1.19-0.20220421211855-0d412c9fbeb1
	github.com/dchest/uniuri v1.2.0
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/gen2brain/beeep v0.0.0-20220909211152-5a9ec94374f6
	github.com/gliderlabs/ssh v0.3.5
	github.com/go-kit/kit v0.12.0
	github.com/google/go-cmp v0.5.9
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/shlex v0.0.0-20181106134648-c34317bd91bf
	github.com/gorilla/websocket v1.5.0
	github.com/gosuri/uilive v0.0.4 // indirect
	github.com/gosuri/uiprogress v0.0.1 // indirect
	github.com/hashicorp/go-multierror v1.1.1
	github.com/heroku/rollrus v0.2.0
	github.com/hooklift/assert v0.1.0 // indirect
	github.com/influxdata/influxdb1-client v0.0.0-20200827194710-b269163b24ab // indirect
	github.com/jpillora/chisel v1.9.1
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/oklog/run v1.1.1-0.20200508094559-c7096881717e
	github.com/olebedev/emitter v0.0.0-20190110104742-e8d1457e6aee
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pborman/ansi v1.0.0
	github.com/prometheus/client_golang v1.17.0
	github.com/rs/xid v1.5.0
	github.com/sirupsen/logrus v1.9.0
	github.com/spf13/cobra v1.7.0
	github.com/tj/go v1.8.7
	github.com/tj/go-update v2.2.5-0.20200519121640-62b4b798fd68+incompatible
	github.com/ulikunitz/xz v0.5.8 // indirect
	golang.org/x/crypto v0.12.0
	google.golang.org/grpc v1.58.2
	google.golang.org/protobuf v1.31.0
)

require (
	github.com/eiannone/keyboard v0.0.0-20220611211555-0d226195f203
	github.com/google/go-github/v55 v55.0.0
	github.com/stretchr/testify v1.7.0
	golang.org/x/exp v0.0.0-20220407100705-7b9b53b0aca4
	golang.org/x/term v0.12.0
)

require (
	github.com/ProtonMail/go-crypto v0.0.0-20230217124315-7d5c6f04bbb8 // indirect
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cloudflare/circl v1.3.3 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-toast/toast v0.0.0-20190211030409-01e6764cf0a4 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jpillora/sizestr v1.0.0 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.4.1-0.20230718164431-9a2bf3000d16 // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/procfs v0.11.1 // indirect
	github.com/rollbar/rollbar-go v1.0.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tadvi/systray v0.0.0-20190226123456-11a2b8fa57af // indirect
	golang.org/x/net v0.14.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	golang.org/x/sys v0.12.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230711160842-782d3b101e98 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/gliderlabs/ssh => github.com/owenthereal/ssh v0.2.3-0.20230930050338-c49eb9cc924f
	golang.org/x/crypto => github.com/tg123/sshpiper.crypto v0.13.0-20230910
)
