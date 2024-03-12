package auditor

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/trap-bytes/hauditor/utils"
)

func xFrameOptionsAudit(resphdrs map[string][]string) {

	if _, ok := resphdrs[XFrameOptionsHeader]; !ok {
		if _, ok := resphdrs[ContentSecurityPolicyHeader]; !ok {
			fmt.Printf(utils.Colorize("X-Frame-Options", "red", true) + " header missing\n")
			redissues++
		} else if !strings.Contains(resphdrs[ContentSecurityPolicyHeader][0], "frame-ancestors") {
			fmt.Printf(utils.Colorize("X-Frame-Options", "red", true) + " header missing\n")
			redissues++
		} else if !strings.Contains(resphdrs[ContentSecurityPolicyHeader][0], "frame-ancestors 'self'") && !strings.Contains(resphdrs[ContentSecurityPolicyHeader][0], "frame-ancestors 'none'") {
			fmt.Print("Possibly insecure frame-ancestor value in " + utils.Colorize("Content-Security-Policy", "red", true) + " Header. Consider using 'none' or 'self'\n")
			yellowissues++
		}
	} else if !strings.EqualFold(resphdrs[XFrameOptionsHeader][0], "DENY") && !strings.EqualFold(resphdrs[XFrameOptionsHeader][0], "SAMEORIGIN") {
		fmt.Printf("Insecure "+utils.Colorize("X-Frame-Options", "red", true)+" header value: "+utils.Colorize("%s", "", true), resphdrs[XFrameOptionsHeader][0])
		redissues++
	}
}

func xContentTypeOptionsAudit(resphdrs map[string][]string) {
	if _, ok := resphdrs[XContentTypeOptionsHeader]; !ok {
		fmt.Printf(utils.Colorize("X-Content-Type-Options", "red", true) + " header missing\n")
		redissues++
	} else if resphdrs[XContentTypeOptionsHeader][0] != "nosniff" {
		fmt.Print("Insecure " + utils.Colorize("X-Content-Type-Options", "red", true) + " header. Consider using 'nosniff'\n")
		redissues++
	}
}

func strictTransportSecurityAudit(resphdrs map[string][]string) {
	if _, ok := resphdrs[StrictTransportSecurityHeader]; !ok {
		fmt.Printf(utils.Colorize("Strict-Transport-Security", "red", true) + " header missing\n")
		redissues++
	}
}

func contentSecurityPolicyAudit(resphdrs map[string][]string) {
	if _, ok := resphdrs[ContentSecurityPolicyHeader]; !ok {
		fmt.Printf(utils.Colorize("Content-Security-Policy", "red", true) + " header missing\n")
		redissues++
	} else {
		cspDirectiveAudit(resphdrs[ContentSecurityPolicyHeader])
	}
}

func cspDirectiveAudit(csp []string) {
	var scriptSrc bool = false
	var defaultSrc bool = false

	directives := extractCSPDirectives(csp)

	if values, ok := directives["script-src"]; ok {
		scriptSrc = true
		sources := strings.Fields(values)
		checkDangerousSource(sources, "script-src")
	}

	if values, ok := directives["default-src"]; ok {
		sources := strings.Fields(values)
		defaultSrc = true
		if _, ok := directives["script-src"]; ok { // if script-src is defined, no need to report dangerous configurations since if any, they'll be reported in that section

			for _, source := range sources {
				if source == "*" {
					fmt.Print(utils.Colorize("Content-Security-Policy", "red", true) + " dangerous source in " + utils.Colorize("default-src:", "", true) + " should not contain " + utils.Colorize("'*'", "magenta", true) + " as a source.\n")
					redissues++
				}
			}
		} else { // if script-src is not defined, we need to be strict on default-src values since they'll be used as fallback for script-src
			checkDangerousSource(sources, "default-src")
		}
	}

	if !scriptSrc && !defaultSrc {
		fmt.Print(utils.Colorize("Content-Security-Policy", "red", true) + " no " + utils.Colorize("script-src", "", true) + " directive defined, this could allow the execution of scripts from untrusted sources\n")
		redissues++
	}

}

func checkDangerousSource(sources []string, directive string) {
	nonHttpUrlPattern := regexp.MustCompile(`^((\*|[a-zA-Z0-9.-]+)\.)+[a-zA-Z]{2,}$`)
	for _, source := range sources {
		switch source {
		case "'unsafe-inline'":
			fmt.Printf(utils.Colorize("Content-Security-Policy", "red", true)+" dangerous source in "+utils.Colorize("%s: ", "", true)+utils.Colorize("'unsafe-inline'", "magenta", true)+" allows the execution of unsafe in-page scripts and event handlers.\n", directive)
			redissues++
		case "data":
			fmt.Print(utils.Colorize("Content-Security-Policy", "red", true)+" dangerous source in "+utils.Colorize("%s: ", "", true)+utils.Colorize("'data:'", "", true)+" URI allows the execution of unsafe scripts.\n", directive)
			redissues++
		case "*":
			fmt.Print(utils.Colorize("Content-Security-Policy", "red", true)+" dangerous source in "+utils.Colorize("%s: ", "", true)+"should not allow "+utils.Colorize("'*'", "", true)+" as a source.\n", directive)
			redissues++
		case "http:":
			fmt.Print(utils.Colorize("Content-Security-Policy", "red", true)+" dangerous source in "+utils.Colorize("%s: ", "", true)+utils.Colorize("'http:'", "magenta", true)+" allows the execution of unsafe scripts.\n", directive)
			redissues++
		case "https:":
			fmt.Print(utils.Colorize("Content-Security-Policy", "red", true)+" dangerous source in "+utils.Colorize("%s: ", "", true)+utils.Colorize("'https:'", "magenta", true)+" allows the execution of unsafe scripts.\n", directive)
			redissues++
		default:
			parsedURL, err := url.Parse(source)
			if err != nil {
				fmt.Println("Error parsing URL:", err)
			} else {
				if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
					if parsedURL.Host != "" {
						fmt.Printf(utils.Colorize("Content-Security-Policy", "yellow", true)+" possible dangerous source in "+utils.Colorize("%s: ", "", true)+"Make sure that "+utils.Colorize(source, "blue", true)+" is not hosting JSONP endpoints\n", directive)
						yellowissues++
					}
				} else if nonHttpUrlPattern.MatchString(source) {
					fmt.Printf(utils.Colorize("Content-Security-Policy", "yellow", true)+" possible dangerous source in "+utils.Colorize("%s: ", "", true)+"Make sure that "+utils.Colorize(source, "blue", true)+" is not hosting JSONP endpoints\n", directive)
					yellowissues++
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
