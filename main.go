package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/trap-bytes/hauditor/auditor"
	"github.com/trap-bytes/hauditor/utils"
)

func main() {
	var urlFlag string
	var fileFlag string
	var proxy string
	var cookie string
	var header string
	var method string
	var body string
	var timeout int
	var jsonOutput bool
	var client *http.Client

	flag.StringVar(&urlFlag, "t", "", "Specify the target URL (e.g., domain.com or https://domain.com)")
	flag.StringVar(&fileFlag, "f", "", "Specify the file containing target URLs (e.g., domains.txt)")
	flag.StringVar(&method, "m", "HEAD", "HTTP method (HEAD, GET, POST, PUT, etc.)")
	flag.StringVar(&body, "b", "", "Request body if using POST or PUT")
	flag.StringVar(&proxy, "p", "", "Specify the proxy URL (e.g., 127.0.0.1:8080)")
	flag.StringVar(&cookie, "c", "", "Specify cookies (e.g., user_token=g3p21ip21h; )")
	flag.StringVar(&header, "r", "", "Specify headers (e.g., Myheader: test )")
	flag.IntVar(&timeout, "timeout", 10, "Specify connection timeout in seconds")
	flag.BoolVar(&jsonOutput, "j", false, "Output results in JSON format")

	helpFlag := flag.Bool("h", false, "Display help")

	flag.Parse()

	originalStdout := os.Stdout
	if jsonOutput {
		os.Stdout = nil
	}

	utils.PrintBanner()

	if *helpFlag {
		utils.PrintHelp()
		return
	}

	err := utils.ValidateTargetFlags(urlFlag, fileFlag)
	if err != nil {
		fmt.Println(err)
		return
	}

	if len(proxy) > 0 {
		if utils.IsValidProxy(proxy) {
			fmt.Println("Using proxy:", proxy)
			client, err = utils.CreateHTTPClientWProxy(proxy, timeout)
			if err != nil {
				fmt.Println(err)
				return
			}
		} else {
			fmt.Println("Invalid proxy:", proxy)
			fmt.Println("Please insert a valid proxy in the ip:port format")
			return
		}
	} else {
		client = &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		}
	}

	if method == "" {
		method = "HEAD"
	} else {
		method = strings.ToUpper(method)
	}

	if (method == "POST" || method == "PUT") && body == "" {
		fmt.Println("If you use POST or put PUT, you must supply a body")
		return
	}

	if urlFlag != "" {
		urlFlag, err := utils.ValidateUrl(urlFlag)
		if err != nil {
			fmt.Printf("Error: %v\n\n", err)
			return
		}

		target := auditor.Target{
			URL:    urlFlag,
			Proxy:  proxy,
			Cookie: cookie,
			Header: header,
			Client: client,
			Method: auditor.RequestMethod{
				Verb: method,
				Body: body,
			},
		}

		ok, result := target.ProcessTarget(false)

		if !ok {
			fmt.Println("Error processing target")
			return
		}

		os.Stdout = originalStdout

		if jsonOutput {
			b, err := json.Marshal(result)
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println(string(b))
		} else {
			for _, r := range result.Responses {
				for _, msg := range r.ConsoleMessages {
					fmt.Println(msg)
				}
			}
		}
	} else {
		fmt.Printf(utils.Colorize("Processing targets from file: %s\n", "", true), fileFlag)

		entries, err := utils.ReadTargetsFromFile(fileFlag)
		if err != nil {
			fmt.Println("Error reading targets:", err)
			return
		}

		results := make([]auditor.TargetResponse, len(entries))

		for i, url := range entries {
			validUrl, err := utils.ValidateUrl(url)
			if err != nil {
				fmt.Printf("Error: %v\n\n", err)
				return
			}
			target := auditor.Target{
				URL:    validUrl,
				Proxy:  proxy,
				Cookie: cookie,
				Header: header,
				Client: client,
				Method: auditor.RequestMethod{
					Verb: method,
					Body: body,
				},
			}
			ok, result := target.ProcessTarget(true)

			if !ok {
				fmt.Println("Error processing target")
				return
			}

			results[i] = result
		}

		os.Stdout = originalStdout

		if jsonOutput {
			b, err := json.Marshal(results)
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println(string(b))
		} else {
			for _, result := range results {
				for _, r := range result.Responses {
					for _, msg := range r.ConsoleMessages {
						fmt.Println(msg)
					}
				}
			}
		}
	}
}
