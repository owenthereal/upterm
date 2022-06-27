// +heroku goVersion 1.18
// +heroku install ./cmd/uptermd/...

module github.com/owenthereal/upterm

go 1.18

require (
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/apex/log v1.9.0 // indirect
	github.com/bradfitz/iter v0.0.0-20191230175014-e8f45d346db8 // indirect
	github.com/buger/goterm v0.0.0-20200322175922-2f3e71b85129 // indirect
	github.com/c4milo/unpackit v0.0.0-20170704181138-4ed373e9ef1c // indirect
	github.com/creack/pty v1.1.19-0.20220329111840-2e47437b1ffb
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/gen2brain/beeep v0.0.0-20220402123239-6a3042f4b71a
	github.com/gliderlabs/ssh v0.2.2
	github.com/go-kit/kit v0.12.0
	github.com/google/go-cmp v0.5.5
	github.com/google/go-github v17.0.0+incompatible
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/shlex v0.0.0-20181106134648-c34317bd91bf
	github.com/gorilla/websocket v1.5.0
	github.com/gosuri/uilive v0.0.4 // indirect
	github.com/gosuri/uiprogress v0.0.1 // indirect
	github.com/hashicorp/go-multierror v1.0.0
	github.com/heroku/rollrus v0.1.1
	github.com/hooklift/assert v0.1.0 // indirect
	github.com/influxdata/influxdb1-client v0.0.0-20200827194710-b269163b24ab // indirect
	github.com/jpillora/chisel v0.0.0-20190724232113-f3a8df20e389
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/oklog/run v1.1.1-0.20200508094559-c7096881717e
	github.com/olebedev/emitter v0.0.0-20190110104742-e8d1457e6aee
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pborman/ansi v0.0.0-20160920233902-86f499584b0a
	github.com/prometheus/client_golang v1.12.1
	github.com/rs/xid v1.4.0
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.4.0
	github.com/tj/go v1.8.6
	github.com/tj/go-update v2.2.5-0.20200519121640-62b4b798fd68+incompatible
	github.com/ulikunitz/xz v0.5.8 // indirect
	golang.org/x/crypto v0.0.0-20210915214749-c084706c2272
	google.golang.org/grpc v1.45.0
	google.golang.org/protobuf v1.28.0
)

require (
	github.com/eiannone/keyboard v0.0.0-20220611211555-0d226195f203
	golang.org/x/exp v0.0.0-20220407100705-7b9b53b0aca4
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.1 // indirect
	github.com/fsnotify/fsnotify v1.4.7 // indirect
	github.com/go-kit/log v0.2.0 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-toast/toast v0.0.0-20190211030409-01e6764cf0a4 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jpillora/sizestr v0.0.0-20160130011556-e2ea2fa42fb9 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/rollbar/rollbar-go v1.0.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tadvi/systray v0.0.0-20190226123456-11a2b8fa57af // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20210917145530-b395a37504d4 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace (
	github.com/gliderlabs/ssh => github.com/owenthereal/ssh v0.2.3-0.20220627151847-686f8d2798bd
	golang.org/x/crypto => github.com/owenthereal/upterm.crypto v0.0.0-20220627151006-26fac2f27e49
)
