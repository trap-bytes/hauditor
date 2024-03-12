package main

import (
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/trap-bytes/hauditor/auditor"
	"github.com/trap-bytes/hauditor/utils"
)

func main() {

	utils.PrintBanner()

	var urlFlag string
	var fileFlag string
	var proxy string
	var cookie string
	var header string
	var method string
	var body string
	var timeout int
	var client *http.Client

	flag.StringVar(&urlFlag, "t", "", "Specify the target URL (e.g., domain.com or https://domain.com)")
	flag.StringVar(&fileFlag, "f", "", "Specify the file containing target URLs (e.g., domains.txt)")
	flag.StringVar(&method, "m", "HEAD", "HTTP method (HEAD, GET, POST, PUT, etc.)")
	flag.StringVar(&body, "b", "", "Request body if using POST or PUT")
	flag.StringVar(&proxy, "p", "", "Specify the proxy URL (e.g., 127.0.0.1:8080)")
	flag.StringVar(&cookie, "c", "", "Specify cookies (e.g., user_token=g3p21ip21h; )")
	flag.StringVar(&header, "r", "", "Specify headers (e.g., Myheader: test )")
	flag.IntVar(&timeout, "timeout", 10, "Specify connection timeout in seconds")

	helpFlag := flag.Bool("h", false, "Display help")

	flag.Parse()

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

		target.ProcessTarget(false)
	} else {
		fmt.Printf(utils.Colorize("Processing targets from file: %s\n", "", true), fileFlag)

		entries, err := utils.ReadTargetsFromFile(fileFlag)
		if err != nil {
			fmt.Println("Error reading targets:", err)
			return
		}

		for _, url := range entries {
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
			target.ProcessTarget(true)
		}
	}
}
