package main

import (
	"fmt"
	"github.com/michalslomczynski/vuln-wo-errata-api-test/system"
	"github.com/michalslomczynski/vuln-wo-errata-api-test/systemcve"
	"golang.org/x/exp/slog"
	"net/http"
	"net/url"
	"os"
)

func printSystemsWithUnfixedCVEs(client http.Client) {
	systems := system.GetAllSystems(client)

	for _, systemID := range systems {
		fixed, unfixed := systemcve.GetSystemCVEsCount(client, systemID)
		if unfixed != 0 {
			fmt.Printf("%s fixed:%d unfixed:%d\n", systemID, fixed, unfixed)
			//return
		}
	}
}

func printSystemCVEsCount(client http.Client, systemID string) {
	//"19a4c80e-1f94-4473-a943-dc909946cb2d"
	fmt.Println(systemcve.GetSystemCVEsCount(client, systemID))
}

func printSystemCVEsWithRemediationManual(client http.Client) {
	//systems := system.GetAllSystems(client)

	for _, systemID := range []string{"174d7f1b-a4b0-4ccf-8807-c3a7c3229f74"} {
		cves := systemcve.GetSystemCVEsWithRemediation(client, systemID, "true,false", 0)
		if len(cves) > 0 {
			for _, cve := range cves {
				fmt.Println(cve)
			}
			fmt.Println(systemID)
			return
		}
	}
}

func init() {
	level := new(slog.LevelVar)
	level.Set(slog.LevelError)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
}

func main() {
	proxyUrl, err := url.Parse(os.Getenv("PROXY"))
	if err != nil {
		slog.Error("failed to parse proxy URL")
	}
	client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	printSystemsWithUnfixedCVEs(client)
	//printSystemCVEsWithRemediationManual(client)
}
