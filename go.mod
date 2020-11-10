// +heroku goVersion 1.15
// +heroku install ./cmd/uptermd/...

module github.com/owenthereal/upterm

go 1.15

require (
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/apex/log v1.9.0 // indirect
	github.com/bradfitz/iter v0.0.0-20191230175014-e8f45d346db8 // indirect
	github.com/buger/goterm v0.0.0-20200322175922-2f3e71b85129 // indirect
	github.com/c4milo/unpackit v0.0.0-20170704181138-4ed373e9ef1c // indirect
	github.com/creack/pty v1.1.12-0.20200804180658-a6c0a376f1d0
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/eiannone/keyboard v0.0.0-20190314115158-7169d0afeb4f
	github.com/gen2brain/beeep v0.0.0-20200420150314-13046a26d502
	github.com/gliderlabs/ssh v0.2.2
	github.com/go-kit/kit v0.9.0
	github.com/google/go-cmp v0.5.0
	github.com/google/go-github v17.0.0+incompatible // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/shlex v0.0.0-20181106134648-c34317bd91bf
	github.com/gorilla/websocket v1.4.1
	github.com/gosuri/uilive v0.0.4 // indirect
	github.com/gosuri/uiprogress v0.0.1 // indirect
	github.com/hashicorp/go-multierror v1.0.0
	github.com/heroku/rollrus v0.1.1
	github.com/hooklift/assert v0.1.0 // indirect
	github.com/influxdata/influxdb1-client v0.0.0-20200827194710-b269163b24ab // indirect
	github.com/jpillora/chisel v0.0.0-20190724232113-f3a8df20e389
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/oklog/run v1.0.0
	github.com/olebedev/emitter v0.0.0-20190110104742-e8d1457e6aee
	github.com/olekukonko/tablewriter v0.0.4
	github.com/pborman/ansi v0.0.0-20160920233902-86f499584b0a
	github.com/prometheus/client_golang v1.3.0
	github.com/rs/xid v1.2.1
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/tj/go v1.8.6
	github.com/tj/go-update v2.2.4+incompatible
	github.com/ulikunitz/xz v0.5.8 // indirect
	golang.org/x/crypto v0.0.0-20200323165209-0ec3e9974c59
	google.golang.org/grpc v1.32.0
	google.golang.org/protobuf v1.25.0
)

replace (
	github.com/gliderlabs/ssh => github.com/owenthereal/ssh v0.2.3-0.20191221201824-4cd54473e34e
	golang.org/x/crypto => github.com/owenthereal/upterm.crypto v0.0.0-20201107051956-5b1abbdea36d
)
