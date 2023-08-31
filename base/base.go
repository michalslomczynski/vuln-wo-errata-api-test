package base

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/exp/slog"
	"io"
	"net/http"
	"os"
	"regexp"
)

const (
	APIurl = "https://console.stage.redhat.com/api/vulnerability/v1"
)

var (
	usr string
	pwd string
)

func init() {
	usr = os.Getenv("USERNAME")
	pwd = os.Getenv("PASSWORD")
}

func BasicHeader() http.Header {
	hdr := http.Header{
		"Content-Type": {"application/json"},
		"Accept":       {"application/json"},
	}
	creds := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", usr, pwd)))
	hdr.Set("authorization", fmt.Sprintf("Basic %s", creds))

	return hdr
}

func PrintResponse(res *http.Response) {
	buff := make([]byte, 1024)
	var err error
	for n := 1; n > 0; n, err = res.Body.Read(buff) {
		if err == io.EOF {
			fmt.Println(string(buff))
			break
		}
		if err != nil {
			panic(err)
		}

		fmt.Println(string(buff))
		buff = make([]byte, 1024)
	}
}

func MatchPattern(line, pattern string) string {
	matched, err := regexp.MatchString(pattern, line)
	if err != nil {
		slog.Error("pattern matching error: ", err)
	}
	if matched {
		return line
	}
	return ""
}
