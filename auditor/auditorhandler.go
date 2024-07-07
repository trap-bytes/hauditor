package auditor

import (
	"bytes"
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

type ResponseStatus int64

const (
	Error ResponseStatus = iota
	Warning
	Success
)

func (rs ResponseStatus) String() string {
	return [...]string{"Error", "Warning", "Success"}[rs]
}

func (rs ResponseStatus) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString([...]string{"Error", "Warning", "Success"}[rs])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

type HeaderResponse struct {
	Header          string
	Status          ResponseStatus
	Messages        []string
	ConsoleMessages []string `json:"-"`
}

type TargetResponse struct {
	URL       string
	Responses []HeaderResponse
	Status    ResponseStatus
}

func (target *Target) ProcessTarget(multi bool) (bool, TargetResponse) {
	resp, err := doRequest(target, target.Method.Verb)
	if err != nil {
		fmt.Printf("error in performing HTTP request to the target: %v", err)
		return false, TargetResponse{}
	}

	if multi {
		fmt.Println()
		fmt.Println("------------------------------------------------------------")
	}
	fmt.Printf("\nAnalyzing "+utils.Colorize("%s", "blue", true)+" security headers\n\n", target.URL)

	ok, responses := handleResponse(target, resp)
	if !ok {
		return false, TargetResponse{}
	}

	// calculate the status of the target based on the status of each header
	var status ResponseStatus
	for _, response := range responses {
		if response.Status == Error {
			status = Error
			break
		} else if response.Status == Warning && status != Error {
			status = Warning
		} else if response.Status == Success && status != Error && status != Warning {
			status = Success
		}
	}

	if status == Success {
		fmt.Printf(utils.Colorize("No security header issues found for %v\n", "green", true), target.URL)
	}

	return true, TargetResponse{
		URL:       target.URL,
		Responses: responses,
		Status:    status,
	}
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

func handleResponse(target *Target, resp *http.Response) (bool, []HeaderResponse) {
	if resp.StatusCode == http.StatusForbidden {
		req, err := http.NewRequest(target.Method.Verb, target.URL, strings.NewReader(target.Method.Body))
		if err != nil {
			fmt.Printf("Error creating a %s request for %s: %v\n", target.Method.Verb, target.URL, err)
			return false, nil
		}

		err = setHeaders(req, target.Cookie, target.Header)
		if err != nil {
			fmt.Println(err)
			return false, nil
		}

		req.Header.Set("User-Agent", "curl/7.81.0")

		resp, err = target.Client.Do(req)
		if err != nil {
			fmt.Println(err)
			return false, nil
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode < http.StatusBadRequest {
		return true, auditHeaders(resp.Header)
	} else {
		return retryGet(target)
	}
}

func retryGet(target *Target) (bool, []HeaderResponse) {

	getResp, err := doRequest(target, http.MethodGet)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return false, nil
	}

	if getResp.StatusCode >= http.StatusBadRequest {
		fmt.Printf("Error making the GET request to %s : \"%v\" HTTP Error code\n\n", target.URL, getResp.Status)
		return false, nil
	} else {
		return true, auditHeaders(getResp.Header)
	}
}

func auditHeaders(resphdrs http.Header) []HeaderResponse {
	var responses []HeaderResponse = []HeaderResponse{}

	normalizedResphdrs := make(map[string][]string)
	for key, values := range resphdrs {
		normalizedResphdrs[strings.ToLower(key)] = values
	}

	for _, sechdr := range SecurityHeaders {

		switch sechdr {
		case XFrameOptionsHeader:
			responses = append(responses, xFrameOptionsAudit(normalizedResphdrs))

		case XContentTypeOptionsHeader:
			responses = append(responses, xContentTypeOptionsAudit(normalizedResphdrs))

		case StrictTransportSecurityHeader:
			responses = append(responses, strictTransportSecurityAudit(normalizedResphdrs))

		case ContentSecurityPolicyHeader:
			responses = append(responses, contentSecurityPolicyAudit(normalizedResphdrs))
		}
	}

	return responses
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
