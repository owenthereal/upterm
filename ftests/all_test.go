package ftests

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func Test_all(t *testing.T) {
	testTargets := []struct {
		name       string
		testServer TestServer
	}{
		{
			name:       "single node",
			testServer: singleNodeServer,
		},
		{
			name:       "multi node",
			testServer: router,
		},
	}

	testCases := []func(*testing.T, TestServer){
		testClientAttachHostWithSameCommand,
		testClientAttachHostWithDifferentCommand,
		testHostFailToShareWithoutPrivateKey,
	}

	for _, target := range testTargets {
		for _, test := range testCases {
			targetLocal := target
			testLocal := test

			t.Run(funcName(testLocal)+"/"+targetLocal.name, func(t *testing.T) {
				t.Parallel()
				testLocal(t, targetLocal.testServer)
			})
		}
	}
}

func funcName(i interface{}) string {
	name := runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
	split := strings.Split(name, ".")

	return split[len(split)-1]
}
