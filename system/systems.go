package system

import (
	"bufio"
	"fmt"
	"github.com/michalslomczynski/vuln-wo-errata-api-test/base"
	"golang.org/x/exp/slog"
	"net/http"
	"regexp"
)

const (
	pageSize = 5000
)

func getUUID(line string) string {
	if match := base.MatchPattern(line, "\"id\":"); match != "" {
		re := regexp.MustCompile("[0-9a-fA-F]{8}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{12}")
		return re.FindString(match)
	}
	return ""
}

func getDisplayName(line string) string {
	return base.MatchPattern(line, "\"display_name\":")
}

func getSystemIDsFromResponse(res *http.Response) ([]string, error) {
	result := make([]string, 0)
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if name := getDisplayName(line); name != "" {
			slog.Info(name)
		}
		if uuid := getUUID(line); uuid != "" {
			slog.Info("uuid: ", uuid)
			result = append(result, uuid)
		}
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func GetAllSystems(client http.Client) []string {
	url := fmt.Sprintf("%s/systems?page_size=%d", base.APIurl, pageSize)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		slog.Error("failed to create new HTTP request: ", err)
	}
	req.Header = base.BasicHeader()

	res, err := client.Do(req)
	if err != nil {
		slog.Error("failed to make http request: ", err)
	}

	slog.Debug("Systems request: ", res.Status)

	ids, err := getSystemIDsFromResponse(res)
	if err != nil {
		slog.Error("failed to get list of system IDs")
	}

	return ids
}
