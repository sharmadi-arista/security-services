package main

import (
	"context"
	"flag"
	"os"

	"github.com/openconfig/security-services/cmd"
	"github.com/spf13/pflag"
	"k8s.io/klog"
)

var (
	flagset = map[string]string{
		"logtostderr":     "false",
		"alsologtostderr": "false",
		"stderrthreshold": "info",
	}
)

func main() {
	// Import flags into pflags that are set in other flag packages.
	klog.InitFlags(nil)
	for k, v := range flagset {
		if f := flag.Lookup(k); f != nil {
			f.Value.Set(v)
			f.DefValue = v
		}
	}
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	rootCmd := cmd.New()
	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		os.Exit(1)
	}
}
