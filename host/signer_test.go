package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const (
	// Passphrase is "1234"
	rsaPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBEESOQn3
hoU95qcZuP7CjjAAAAEAAAAAEAAAIXAAAAB3NzaC1yc2EAAAADAQABAAACAQCt//y3H4he
Ri1+3bO+FsqKyGTw5YQnu6MChEaDJY2SJqFCHGEwBAWGsuaDZPb6P+V16I5u2H+MtKBWDb
kVK9760DkAFimuQ4XTtIzPhyb+Jc95wvNW6pAYXoetVlZIbzNzMEykE41kOMq19SNS3snv
E5mYzfd2B6AGw3T2SubfF6G0staxtEYwlsWP/N+YIR4yLz11bxwuuTee/eMldvKZfzQQXI
uopANU2mnAmoOqsG0G+DKNuXw7F7zd7lxus8zBF3fszur7Sc9APbWab5phJXWzE81ME2Z0
Rro3/l/5mD3YqmS6+jyIqlvqR150Uf/2rKawVgzxZWvQhe1+gGIktavL85dO9VnxA/BASY
M0caqFY/KwVpAs/mZ18SpjgPaEzm3H5eeTJRFMrwRusyunPTDv8lmAAXsr/ZMhd1gBkDiG
E/YuTfekv8rMbkZNeB2HuXavcRTuCqY8y44ehe+sRug9nwykPnfRqjIeAm9zh+zknfJGl5
TONHKnEj5tudpUvTd38ZnOM+CTzMHbSDOwkSLAp9mCzrbWc6OIeVqsqibPmia4SxyP7wxn
szfH1MOkuCmphiCzk4nicYDhMW6jjXhRKok4yNIU9wqj0MMEKS3RKblAzCu7VFVTDrLSJI
zs7Ch0RIuGnVTQ5S4O156Kr9hL535k6c6/NUXbylXtuwAAB0BoB2MIcsYKGTdrHayerk4e
O+5ACB6GxBYT0xEQ9959ioF+RgFaXiGDv9fYrJSjUp11uok0LWoLzGXD0w2/+LCMiOO75R
DSmiPRdQbfMgm8p+etBF5QHg4tcVnMjYHCqFtPDwyyYRHwHmYi9qx+iZqBooEgyExmuahu
oT/6Z5ntycBo9543oDVQVJOMYDNh/u9AC2Wke7j7LufhKNg/Rd3Gg1BWI9IwVCeU8A4Gqa
Z9fnvrkTRcKFYF5fakxXKnfdHNQco3zxdXGEnbcY34PR/CD5R0J666zoJEeYp25jJd9Opb
MBKss07yrZq90KIQEveVC6L7tCJpNmRXHN1iQpkq+WKSlX/lMxTanW7KFcKU6qFhFi2m4V
eEGPlAU6tOpsYthkElBhxeBRzwW4lzCDfZErYbtNFGiT+xGxVIzkQIQdH++Y8waNHZ4mNv
xX5a0/CxMkipUS0CDfZ8XEwHDkQDko1cdwq13PD+AGZvWIDP20EQ3MqrWqb/ho0QJbWLd7
W6QlwxVewUxfFlBdnpGFpin0RDXsQUZ2IxNuIzzpcAslILtBhQdfXkMAwomQWhs0qxiyEc
W9jMyYv20J+oR+wc8xVZEBw7KfM52Zl9J90t0nBwghswiykx4BYzu9PwY52gdJOWkMZq1b
cEPXBa7Y/nAPObXQp/hWwfhKdi5WjXiXCI//nMshRm1bLRqAmFVex9K6UpEY3Svl/fDBe3
fR21qPi7zEmbZXh9abrPibF6UGZxl54yzKdSS3J/9BletdagYo+WhcV460Dg2hjy2XrrpM
tLcmUQegINRmr3mJ2nHHw5b6X61UJDto/AgEDlZuTh35YBnUwibi7dlbepRfJ8XgWhHxM+
21Qg+nmD+I2u8a8d2gnuTiv7m4A/M/bA9E4YbaligZvw4w7Zd18cBzYgb43nNiV82tBFz9
hCd+9HlwNQnaJ9EL/tyFwJ1IkyQCF3YLTV3KaMUvHWDXYdNbktnrSgJazQgou7KNjN0nbm
rtKAU1+iN/QgmBSOD3Rq6WnP2co4EqocEluBBb4eF6yOQ3jEd+icRkL/a0Wpc9NU7jMPll
HfDIzaaGVGSFB13pYdIZNckgctpHGZnnB1jhLzaWzwjumBmt1g//wN3HeMxiQfFMrl78yP
qJjceag13J+QdrSawLzf/ulXUALQKnpdPnvuwGlXnUbpXrqtP/J+qJwjpyuit8an5k7foI
yK/1pPw0gz9j/KsebhXuZF7gxlZZCtkbdmCtrEVOqo/yIX02eGshFhO/h76QXvi1hz4SR2
H6oB1KapvJlqd+txTIDf/zhlPP7vHPXsMUcumclsg+iP/mpleo51TFpD456A0g905fnjJr
OKBftowi9IhYZM8bPKis1K7NWfz3uE90Mc8jky0e6XzlxKi4rF9ZKMuvm9b/QA9v6HYUNJ
kadcq5GaVjL8hlgtMnRYDyClYoPsqyyuFP+rjWfEUPWANKzFR5rku6l2e5nTxm756azYDs
XDupgd4Oo5w7KONgkLJffF+X4ClLfWnrlIm2EWF1Tw0E7XleaccnggUNUMg+4uY12IG8zb
4CyDE4vFgeqY9+d3fxg/d33aOVyFB60hiqmYhni+Tf7z1yKRoqE44SiIEF+GDmnAaJuz91
EO9r1P5xpW22Fgp3MFaqZh2Jrp9g5Ai4UC9mxQvXK/Y+He582IMoXaXEpp7SuIDOuDSv0i
uU2Pm47jiPRFFIOtv1Zf6tJMAkY2wlN4W2nl5GdQwWQ7CNzaTtfquX1ckQIV8wlpbZH9Wn
myfnyc90/5ZQUlmX1nwg7UatSky1DxJfIMpePWqDNaeCJxKnMW/spO5PgEar/TKVzvYRh7
0FCP0+c44GzgMkvx3HuPQro4LEeHUbeWjtQCKj1Vh/e8BIoUV4iw7vWJCk2/GzDm7QhcRD
1rKbFgHs4aOg0gkCQOfHuE5jNJrBYO2PdmuQOT8v1um02yv1simYmmetLg+aW1t7akvbWM
XztiGLpnwCRY3KemwNydG/5d/D+FvAovg8I7zAjLTIlnicL3P+MMt0O05e7mYYZXGKfb+S
Md0uKlDJ+7DunkAH3P2NQe0AJVI6oX4oko20gx+3+XhL6SIsp3/Bo1KFG2utncUgnK1OMX
ezOenHBL3QdMsZHEmvgX+GqttoFO/ILqzXeRcn7bC0Vc1TdceDDjsVeWDiNlx6kRHCyYCM
YXxsw1NVcpHtL9gAhqa8cyuHFpUCFA98EE0QX3bqbYtDlidqqsVUdprxXi3GfnpdhdRueM
SVF3wK7yXwu2554Rs/HuLf+rxOrHsF8ZfSWAxtdDqxwuFt5UFstr9HupRgt8ik8XodIVdb
WDzQFezZ5FudCmO23iNsXuUxs/j8lAYAC4gmTxoFYhAEhulUCjv+dVRe9lP0W1uygohVho
XBcvbGIDxNBoIlPFRM+bqvIDC1sQi3MIh3l/NZQxxIkW/+I4uClYpmNGXPZaNZNhpdv1PJ
a9rQ==
-----END OPENSSH PRIVATE KEY-----
`
	// nolint
	rsaPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCt//y3H4heRi1+3bO+FsqKyGTw5YQnu6MChEaDJY2SJqFCHGEwBAWGsuaDZPb6P+V16I5u2H+MtKBWDbkVK9760DkAFimuQ4XTtIzPhyb+Jc95wvNW6pAYXoetVlZIbzNzMEykE41kOMq19SNS3snvE5mYzfd2B6AGw3T2SubfF6G0staxtEYwlsWP/N+YIR4yLz11bxwuuTee/eMldvKZfzQQXIuopANU2mnAmoOqsG0G+DKNuXw7F7zd7lxus8zBF3fszur7Sc9APbWab5phJXWzE81ME2Z0Rro3/l/5mD3YqmS6+jyIqlvqR150Uf/2rKawVgzxZWvQhe1+gGIktavL85dO9VnxA/BASYM0caqFY/KwVpAs/mZ18SpjgPaEzm3H5eeTJRFMrwRusyunPTDv8lmAAXsr/ZMhd1gBkDiGE/YuTfekv8rMbkZNeB2HuXavcRTuCqY8y44ehe+sRug9nwykPnfRqjIeAm9zh+zknfJGl5TONHKnEj5tudpUvTd38ZnOM+CTzMHbSDOwkSLAp9mCzrbWc6OIeVqsqibPmia4SxyP7wxnszfH1MOkuCmphiCzk4nicYDhMW6jjXhRKok4yNIU9wqj0MMEKS3RKblAzCu7VFVTDrLSJIzs7Ch0RIuGnVTQ5S4O156Kr9hL535k6c6/NUXbylXtuw==`

	// Passphrase is "1234"
	ed25519PriavteKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCGNomvLJ
kXLr+TqkGZ2fuiAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIA9dIfLyILssYzKI
VY7UQenn2Il6cUeeYppVwDSAiqPzAAAAsAied6o/EzONSz0GmRvzUIUmK899O+N/ARFc9c
sSq5R8Qu+iqFOtgNFnPI1/wu22agUYxs3h6Su4Jv6WbySJpJhHhIN/6pZ4DZgj4zWGGSJl
5Kt2/q0hzzuxmO6hTGUGLArVXbJEXxTPV/jo/1w8qBYyB1rdKal1dN0OzUlCP1568WR8wq
CUI+b0Gxfqa/HSKlS23Iu7ZeWoMakwvcg5A5M8E/ihBLSDNsCJU8pgZ9FD
-----END OPENSSH PRIVATE KEY-----
`
	// nolint
	ed25519PublicKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA9dIfLyILssYzKIVY7UQenn2Il6cUeeYppVwDSAiqPz jou@oou-ltm.internal.salesforce.com`
)

func Test_signerFromFile(t *testing.T) {
	cases := []struct {
		name       string
		privateKey string
		passphrase string
		errMsg     string
	}{
		{
			name:       "rsa private key wrong passphrase",
			privateKey: rsaPrivateKey,
			passphrase: "wrong passphrase",
			errMsg:     "error decrypting private key",
		},
		{
			name:       "rsa private key correct passphrase",
			privateKey: rsaPrivateKey,
			passphrase: "1234",
		},
		{
			name:       "ed25519 private key wrong passphrase",
			privateKey: ed25519PriavteKey,
			passphrase: "wrong passphrase",
			errMsg:     "error decrypting private key",
		},
		{
			name:       "ed25519 private key correct passphrase",
			privateKey: ed25519PriavteKey,
			passphrase: "1234",
		},
	}

	for _, cc := range cases {
		c := cc
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			tmpfn := filepath.Join(dir, "private_key")
			if err := os.WriteFile(tmpfn, []byte(c.privateKey), 0600); err != nil {
				t.Fatal(err)
			}

			_, err := signerFromFile(tmpfn, func(file string) ([]byte, error) {
				if want, got := tmpfn, file; want != got {
					t.Fatalf("file mismatched, want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
				}

				return []byte(c.passphrase), nil
			})

			if err == nil && c.errMsg != "" {
				t.Fatal("error shouldn't be nil")
			}

			if err != nil && c.errMsg == "" {
				t.Fatalf("error should be nil but it's %s", err.Error())
			}

			if err != nil && !strings.Contains(err.Error(), c.errMsg) {
				t.Fatalf("unexpected error message, want=%q, got=%q", c.errMsg, err.Error())
			}
		})
	}
}
