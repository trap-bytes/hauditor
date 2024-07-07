package auditor

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/trap-bytes/hauditor/utils"
)

func xFrameOptionsAudit(resphdrs map[string][]string) HeaderResponse {
	var response HeaderResponse = HeaderResponse{Header: XFrameOptionsHeader, Status: Success}

	if _, ok := resphdrs[XFrameOptionsHeader]; !ok {
		if _, ok := resphdrs[ContentSecurityPolicyHeader]; !ok {
			response.Status = Error
			response.ConsoleMessages = []string{utils.Colorize("X-Frame-Options", "red", true) + " header missing"}
			response.Messages = []string{"X-Frame-Options header missing"}
		} else if !strings.Contains(resphdrs[ContentSecurityPolicyHeader][0], "frame-ancestors") {
			response.Status = Error
			response.ConsoleMessages = []string{utils.Colorize("X-Frame-Options", "red", true) + " header missing"}
			response.Messages = []string{"X-Frame-Options header missing"}
		} else if !strings.Contains(resphdrs[ContentSecurityPolicyHeader][0], "frame-ancestors 'self'") && !strings.Contains(resphdrs[ContentSecurityPolicyHeader][0], "frame-ancestors 'none'") {
			response.Status = Warning
			response.ConsoleMessages = []string{"Possibly insecure frame-ancestor value in " + utils.Colorize("Content-Security-Policy", "red", true) + " Header. Consider using 'none' or 'self'"}
			response.Messages = []string{"Possibly insecure frame-ancestor value in Content-Security-Policy Header"}
		}
	} else if !strings.EqualFold(resphdrs[XFrameOptionsHeader][0], "DENY") && !strings.EqualFold(resphdrs[XFrameOptionsHeader][0], "SAMEORIGIN") {
		response.Status = Error
		response.ConsoleMessages = []string{"Insecure " + utils.Colorize("X-Frame-Options", "red", true) + " header value: " + utils.Colorize(resphdrs[XFrameOptionsHeader][0], "", true)}
		response.Messages = []string{"Insecure X-Frame-Options header value: " + resphdrs[XFrameOptionsHeader][0]}
	}

	return response
}

func xContentTypeOptionsAudit(resphdrs map[string][]string) HeaderResponse {
	var response HeaderResponse = HeaderResponse{Header: XContentTypeOptionsHeader, Status: Success}

	if _, ok := resphdrs[XContentTypeOptionsHeader]; !ok {
		response.Status = Error
		response.ConsoleMessages = []string{utils.Colorize("X-Content-Type-Options", "red", true) + " header missing"}
		response.Messages = []string{"X-Content-Type-Options header missing"}
	} else if resphdrs[XContentTypeOptionsHeader][0] != "nosniff" {
		response.Status = Error
		response.ConsoleMessages = []string{"Insecure " + utils.Colorize("X-Content-Type-Options", "red", true) + " header. Consider using 'nosniff'"}
		response.Messages = []string{"Insecure X-Content-Type-Options header. Consider using 'nosniff'."}
	}

	return response
}

func strictTransportSecurityAudit(resphdrs map[string][]string) HeaderResponse {
	var response HeaderResponse = HeaderResponse{Header: StrictTransportSecurityHeader, Status: Success}

	if _, ok := resphdrs[StrictTransportSecurityHeader]; !ok {
		response.Status = Error
		response.ConsoleMessages = []string{utils.Colorize("Strict-Transport-Security", "red", true) + " header missing"}
		response.Messages = []string{"Strict-Transport-Security header missing"}
	}

	return response
}

func contentSecurityPolicyAudit(resphdrs map[string][]string) HeaderResponse {
	var response HeaderResponse = HeaderResponse{
		Header:          ContentSecurityPolicyHeader,
		Status:          Success,
		ConsoleMessages: []string{},
		Messages:        []string{},
	}

	if _, ok := resphdrs[ContentSecurityPolicyHeader]; !ok {
		response.Status = Error
		response.ConsoleMessages = []string{utils.Colorize("Content-Security-Policy", "red", true) + " header missing"}
		response.Messages = []string{"Content-Security-Policy header missing"}
	} else {
		cspDirectiveAudit(resphdrs[ContentSecurityPolicyHeader], &response)
	}

	return response
}

func cspDirectiveAudit(csp []string, response *HeaderResponse) {
	var scriptSrc bool = false
	var defaultSrc bool = false

	directives := extractCSPDirectives(csp)

	if values, ok := directives["script-src"]; ok {
		scriptSrc = true
		sources := strings.Fields(values)
		checkDangerousSource(sources, "script-src", response)
	}

	if values, ok := directives["default-src"]; ok {
		sources := strings.Fields(values)
		defaultSrc = true
		if _, ok := directives["script-src"]; ok { // if script-src is defined, no need to report dangerous configurations since if any, they'll be reported in that section

			for _, source := range sources {
				if source == "*" {
					response.Status = Error
					response.ConsoleMessages = append(response.ConsoleMessages, utils.Colorize("Content-Security-Policy", "red", true)+" dangerous source in "+utils.Colorize("default-src:", "", true)+" should not contain "+utils.Colorize("'*'", "magenta", true)+" as a source.")
					response.Messages = append(response.Messages, "Dangerous source in default-src should not contain '*' as a source.")
				}
			}
		} else { // if script-src is not defined, we need to be strict on default-src values since they'll be used as fallback for script-src
			checkDangerousSource(sources, "default-src", response)
		}
	}

	if !scriptSrc && !defaultSrc {
		response.Status = Error
		response.ConsoleMessages = append(response.ConsoleMessages, utils.Colorize("Content-Security-Policy", "red", true)+" no "+utils.Colorize("script-src", "", true)+" directive defined, this could allow the execution of scripts from untrusted sources")
		response.Messages = append(response.Messages, "No script-src directive defined, this could allow the execution of scripts from untrusted sources.")
	}

}

func checkDangerousSource(sources []string, directive string, response *HeaderResponse) {
	nonHttpUrlPattern := regexp.MustCompile(`^((\*|[a-zA-Z0-9.-]+)\.)+[a-zA-Z]{2,}$`)
	for _, source := range sources {
		switch source {
		case "'unsafe-inline'":
			response.Status = Error
			response.ConsoleMessages = append(response.ConsoleMessages, utils.Colorize("Content-Security-Policy", "red", true)+" dangerous source in "+utils.Colorize(directive+": ", "", true)+utils.Colorize("'unsafe-inline'", "magenta", true)+" allows the execution of unsafe in-page scripts and event handlers.")
			response.Messages = append(response.Messages, "Dangerous source in "+directive+": 'unsafe-inline' allows the execution of unsafe in-page scripts and event handlers.")
		case "data":
			response.Status = Error
			response.ConsoleMessages = append(response.ConsoleMessages, utils.Colorize("Content-Security-Policy", "red", true)+" dangerous source in "+utils.Colorize(directive+": ", "", true)+utils.Colorize("'data:'", "", true)+" URI allows the execution of unsafe scripts.")
			response.Messages = append(response.Messages, "Dangerous source in "+directive+": 'data:' URI allows the execution of unsafe scripts.")
		case "*":
			response.Status = Error
			response.ConsoleMessages = append(response.ConsoleMessages, utils.Colorize("Content-Security-Policy", "red", true)+" dangerous source in "+utils.Colorize(directive+": ", "", true)+"should not allow "+utils.Colorize("'*'", "", true)+" as a source.")
			response.Messages = append(response.Messages, "Dangerous source in "+directive+": '*' should not be allowed as a source.")
		case "http:":
			response.Status = Error
			response.ConsoleMessages = append(response.ConsoleMessages, utils.Colorize("Content-Security-Policy", "red", true)+" dangerous source in "+utils.Colorize(directive+": ", "", true)+utils.Colorize("'http:'", "magenta", true)+" allows the execution of unsafe scripts.")
			response.Messages = append(response.Messages, "Dangerous source in "+directive+": 'http:' allows the execution of unsafe scripts.")
		case "https:":
			response.Status = Error
			response.ConsoleMessages = append(response.ConsoleMessages, utils.Colorize("Content-Security-Policy", "red", true)+" dangerous source in "+utils.Colorize(directive+": ", "", true)+utils.Colorize("'https:'", "magenta", true)+" allows the execution of unsafe scripts.")
			response.Messages = append(response.Messages, "Dangerous source in "+directive+": 'https:' allows the execution of unsafe scripts.")
		default:
			parsedURL, err := url.Parse(source)
			if err != nil {
				response.Status = Error
				response.ConsoleMessages = append(response.ConsoleMessages, utils.Colorize("Content-Security-Policy", "red", true)+" invalid source in "+utils.Colorize(directive+": ", "", true)+utils.Colorize(source, "magenta", true))
				response.Messages = append(response.Messages, "Invalid source in "+directive+": "+source)
			} else {
				if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
					if parsedURL.Host != "" {
						if response.Status != Error {
							response.Status = Warning
						}
						response.ConsoleMessages = append(response.ConsoleMessages, utils.Colorize("Content-Security-Policy", "yellow", true)+" possible dangerous source in "+utils.Colorize(directive+": ", "", true)+"Make sure that "+utils.Colorize(source, "blue", true)+" is not hosting JSONP endpoints")
						response.Messages = append(response.Messages, "Possible dangerous source in "+directive+": Make sure that "+source+" is not hosting JSONP endpoints.")
					}
				} else if nonHttpUrlPattern.MatchString(source) {
					if response.Status != Error {
						response.Status = Warning
					}
					response.ConsoleMessages = append(response.ConsoleMessages, utils.Colorize("Content-Security-Policy", "yellow", true)+" possible dangerous source in "+utils.Colorize(directive+": ", "", true)+"Make sure that "+utils.Colorize(source, "blue", true)+" is not hosting JSONP endpoints")
					response.Messages = append(response.Messages, "Possible dangerous source in "+directive+": Make sure that "+source+" is not hosting JSONP endpoints.")
				}
			}
		}
	}
}

func extractCSPDirectives(csp []string) map[string]string {
	directives := make(map[string]string)

	if len(csp) == 0 {
		return directives
	}

	cspHeader := csp[0]
	cspDirectives := strings.Split(cspHeader, ";")

	for _, directive := range cspDirectives {
		directive = strings.TrimSpace(directive)
		parts := strings.SplitN(directive, " ", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]
			directives[key] = value
		}
	}

	return directives
}
