package auditor

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/trap-bytes/hauditor/utils"
)

const (
	XFrameOptionsHeader           = "x-frame-options"
	XContentTypeOptionsHeader     = "x-content-type-options"
	StrictTransportSecurityHeader = "strict-transport-security"
	ContentSecurityPolicyHeader   = "content-security-policy"
)

var SecurityHeaders = []string{
	XFrameOptionsHeader,
	XContentTypeOptionsHeader,
	StrictTransportSecurityHeader,
	ContentSecurityPolicyHeader,
}

type Target struct {
	URL    string
	Proxy  string
	Cookie string
	Header string
	Client *http.Client
	Method RequestMethod
}

type RequestMethod struct {
	Verb string
	Body string
}

var redissues, yellowissues int = 0, 0

func (target *Target) ProcessTarget(multi bool) {
	resp, err := doRequest(target, target.Method.Verb)
	if err != nil {
		fmt.Printf("error in performing HTTP request to the target: %v", err)
		return
	}

	if multi {
		fmt.Println()
		fmt.Println("------------------------------------------------------------")
	}
	fmt.Printf("\nAnalyzing "+utils.Colorize("%s", "blue", true)+" security headers\n\n", target.URL)

	handleResponse(target, resp)
}

func doRequest(target *Target, method string) (*http.Response, error) {
	req, err := http.NewRequest(method, target.URL, strings.NewReader(target.Method.Body))
	if err != nil {
		errorMsg := fmt.Sprintf("Error creating a %s request for %s: %v", method, target.URL, err)
		return nil, errors.New(errorMsg)
	}

	err = setHeaders(req, target.Cookie, target.Header)
	if err != nil {
		return nil, err
	}

	resp, err := target.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return resp, nil
}

func handleResponse(target *Target, resp *http.Response) {
	if resp.StatusCode == http.StatusForbidden {
		req, err := http.NewRequest(target.Method.Verb, target.URL, strings.NewReader(target.Method.Body))
		if err != nil {
			fmt.Printf("Error creating a %s request for %s: %v\n", target.Method.Verb, target.URL, err)
			return
		}

		err = setHeaders(req, target.Cookie, target.Header)
		if err != nil {
			fmt.Println(err)
			return
		}

		req.Header.Set("User-Agent", "curl/7.81.0")

		resp, err = target.Client.Do(req)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode < http.StatusBadRequest {
		auditHeaders(resp.Header, target.URL)
	} else {
		retryGet(target)
	}
}

func retryGet(target *Target) {

	getResp, err := doRequest(target, http.MethodGet)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if getResp.StatusCode >= http.StatusBadRequest {
		fmt.Printf("Error making the GET request to %s : \"%v\" HTTP Error code\n\n", target.URL, getResp.Status)
	} else {
		auditHeaders(getResp.Header, target.URL)
	}
}

func auditHeaders(resphdrs http.Header, targetURL string) {

	normalizedResphdrs := make(map[string][]string)
	for key, values := range resphdrs {
		normalizedResphdrs[strings.ToLower(key)] = values
	}

	for _, sechdr := range SecurityHeaders {

		switch sechdr {
		case XFrameOptionsHeader:
			xFrameOptionsAudit(normalizedResphdrs)

		case XContentTypeOptionsHeader:
			xContentTypeOptionsAudit(normalizedResphdrs)

		case StrictTransportSecurityHeader:
			strictTransportSecurityAudit(normalizedResphdrs)

		case ContentSecurityPolicyHeader:
			contentSecurityPolicyAudit(normalizedResphdrs)
		}
	}

	if redissues == 0 && yellowissues == 0 {
		fmt.Printf(utils.Colorize("No security header issues found for %v\n", "green", true), targetURL)
	}
	redissues, yellowissues = 0, 0
}

func setHeaders(req *http.Request, cookie, customHeader string) error {
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if customHeader != "" {
		headerParts := strings.SplitN(customHeader, ":", 2)
		if len(headerParts) == 2 {
			req.Header.Add(strings.TrimSpace(headerParts[0]), strings.TrimSpace(headerParts[1]))
		} else {
			return fmt.Errorf("invalid header format: %s", customHeader)
		}
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0")
	req.Header.Add("Accept", "*/*")

	return nil
}
