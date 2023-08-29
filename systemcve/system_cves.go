package systemcve

import (
	"bufio"
	"fmt"
	"github.com/michalslomczynski/vuln-wo-errata-api-test/base"
	"log"
	"net/http"
	"regexp"
	"strconv"
)

func systemCVEsURL(systemID string, filters []string) string {
	url := fmt.Sprintf("%s/systems/%s/cves?", base.APIurl, systemID)
	for i, filter := range filters {
		url = fmt.Sprintf("%s%s", url, filter)
		if i != len(filter)-1 {
			url = fmt.Sprintf("%s&", url)
		}
	}
	fmt.Println(url)
	return url
}

// handleLine extracts total_items key from line.
func handleLine(line string) int {
	if match := base.MatchPattern(line, "\"total_items\":"); match != "" {
		re := regexp.MustCompile("[0-9]+")
		totalItemsSubstr := re.FindString(match)
		totalItems, err := strconv.Atoi(totalItemsSubstr)
		if err != nil {
			log.Fatal("total items regexp error: ", err)
		}
		return totalItems
	}
	return -1
}

// getTotalItems iterates over each line in response until total_items value is found.
func getTotalItems(res *http.Response) int {
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		totalItems := handleLine(scanner.Text())
		if totalItems != -1 {
			return totalItems
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal("HTTP response reading error: ", err)
	}

	log.Fatal("total items not found")

	return -1
}

func GetSystemCVEsCount(client http.Client, systemID string) (int, int) {
	fixedCVEs, unfixedCVEs := 0, 0
	for _, filterVal := range []string{"true", "false"} {
		cveURL := systemCVEsURL(systemID, []string{fmt.Sprintf("advisory_available=%s", filterVal)})
		req, err := http.NewRequest("GET", cveURL, nil)
		if err != nil {
			log.Fatal("failed to create new HTTP request: ", err)
		}
		req.Header = base.BasicHeader()

		res, err := client.Do(req)
		if err != nil {
			log.Fatal("failed to make http request: ", err)
		}

		log.Println("System", systemID, "request: ", res.Status)

		total := getTotalItems(res)

		if filterVal == "true" {
			fixedCVEs = total
		} else {
			unfixedCVEs = total
		}
	}

	return fixedCVEs, unfixedCVEs
}