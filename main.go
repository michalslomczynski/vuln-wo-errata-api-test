package main

import (
	"fmt"
	"github.com/michalslomczynski/vuln-wo-errata-api-test/system"
	"github.com/michalslomczynski/vuln-wo-errata-api-test/systemcve"
	"log"
	"net/http"
	"net/url"
	"os"
)

func printSystemsWithUnfixedCVEs(client http.Client) {
	systems := system.GetAllSystems(client)

	for _, systemID := range systems {
		fixed, unfixed := systemcve.GetSystemCVEsCount(client, systemID)
		if fixed-unfixed != 0 {
			fmt.Println(systemID)
			return
		}
	}
}

func printSystemCVEsCount(client http.Client, systemID string) {
	//"19a4c80e-1f94-4473-a943-dc909946cb2d"
	fmt.Println(systemcve.GetSystemCVEsCount(client, systemID))
}

func printSystemCVEsWithRemediationManual(client http.Client) {
	systems := system.GetAllSystems(client)

	for _, systemID := range systems {
		cves := systemcve.GetSystemCVEsWithRemediation(client, systemID, "true,false", 1)
		if len(cves) > 0 {
			for _, cve := range cves {
				fmt.Println(cve)
			}
			fmt.Println(systemID)
			return
		}
	}
}

func main() {
	proxyUrl, err := url.Parse(os.Getenv("PROXY"))
	if err != nil {
		log.Fatal("failed to parse proxy URL")
	}
	client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	printSystemCVEsWithRemediationManual(client)
}
