// +heroku goVersion 1.15
// +heroku install ./cmd/uptermd/...

module github.com/owenthereal/upterm

go 1.15

require (
	github.com/ScaleFT/sshkeys v0.0.0-20181112160850-82451a803681
	github.com/creack/pty v1.1.12-0.20200804180658-a6c0a376f1d0
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/eiannone/keyboard v0.0.0-20190314115158-7169d0afeb4f
	github.com/gen2brain/beeep v0.0.0-20200420150314-13046a26d502
	github.com/gliderlabs/ssh v0.2.2
	github.com/go-kit/kit v0.9.0
	github.com/golang/protobuf v1.3.3
	github.com/google/go-cmp v0.4.0
	github.com/google/shlex v0.0.0-20181106134648-c34317bd91bf
	github.com/gorilla/websocket v1.4.1
	github.com/hashicorp/go-multierror v1.0.0
	github.com/heroku/rollrus v0.1.1
	github.com/jingweno/upterm v0.4.4
	github.com/jpillora/chisel v0.0.0-20190724232113-f3a8df20e389
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
	golang.org/x/crypto v0.0.0-20191029031824-8986dd9e96cf
	google.golang.org/grpc v1.32.0
)

replace (
	github.com/gliderlabs/ssh => github.com/owenthereal/ssh v0.2.3-0.20191221201824-4cd54473e34e
	golang.org/x/crypto => github.com/owenthereal/upterm.crypto v0.0.0-20200329195556-a90c3995fb1c
)
