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

func main() {
	proxyUrl, err := url.Parse(os.Getenv("PROXY"))
	if err != nil {
		log.Fatal("failed to parse proxy URL")
	}
	client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// "19a4c80e-1f94-4473-a943-dc909946cb2d"
	//fmt.Println(systemcve.GetSystemCVEsCount(client, "19a4c80e-1f94-4473-a943-dc909946cb2d"))

	allSystems := system.GetAllSystems(client)

	for _, systemID := range allSystems {
		fixed, unfixed := systemcve.GetSystemCVEsCount(client, systemID)
		if fixed-unfixed != 0 {
			fmt.Println(systemID)
			return
		}
	}
}
