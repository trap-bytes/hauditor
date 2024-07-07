package utils

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	Reset   = "\033[0m"
	Black   = "\033[;30m"
	Red     = "\033[;31m"
	Green   = "\033[;32m"
	Yellow  = "\033[;33m"
	Blue    = "\033[;34m"
	Magenta = "\033[;35m"
	Cyan    = "\033[;36m"
	White   = "\033[;37m"
	Bold    = "\033[1m"
)

var colorMap = map[string]string{
	"reset":   Reset,
	"black":   Black,
	"red":     Red,
	"green":   Green,
	"yellow":  Yellow,
	"blue":    Blue,
	"magenta": Magenta,
	"cyan":    Cyan,
	"white":   White,
	"bold":    Bold,
}

func ValidateTargetFlags(urlFlag, fileFlag string) error {
	if urlFlag != "" && fileFlag != "" {
		return fmt.Errorf("you can supply either a single target or a file, but not both\n Example usage: ./hauditor -t domain.com")
	}

	if urlFlag == "" && fileFlag == "" {
		return fmt.Errorf("please provide a target.\n Example usage: ./hauditor -t domain.com\n Use -h for help")
	}

	return nil
}

func ValidateUrl(inputURL string) (string, error) {
	u, err := url.Parse(inputURL)
	if err != nil {
		return "", fmt.Errorf("Error parsing URL: %v", err)
	}
	//test
	if u.Scheme == "" {
		inputURL = "https://" + inputURL
		u, _ = url.Parse(inputURL)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("Invalid URL scheme")
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
	}

	_, err = net.LookupHost(host)
	if err != nil {
		return "", err
	}

	if port != "" {
		inputURL = fmt.Sprintf("%s://%s:%s%s", u.Scheme, host, port, u.RequestURI())
	} else {
		inputURL = fmt.Sprintf("%s://%s%s", u.Scheme, host, u.RequestURI())
	}

	return inputURL, nil
}

func ReadTargetsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var entries []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		validUrl, err := ValidateUrl(line)
		if err != nil {
			fmt.Printf("Error: %v\n\n", err)
		} else {
			entries = append(entries, validUrl)
		}

	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func CreateHTTPClientWProxy(proxy string, timeout int) (*http.Client, error) {
	parts := strings.Split(proxy, ":")
	proxyIP := parts[0]
	proxyPortStr := parts[1]
	proxyPort, err := strconv.Atoi(proxyPortStr)
	if err != nil {
		return nil, fmt.Errorf("error converting proxy port to integer: %v", err)
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}
	if proxyIP != "" && proxyPort != 0 {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", proxyIP, proxyPort))
		if err != nil {
			return nil, fmt.Errorf("error parsing proxy URL: %v", err)
		}
		client.Transport = &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return client, nil
}

func Colorize(text string, colorName string, bold bool) string {
	colorCode, ok := colorMap[colorName]
	if !ok {
		colorCode = ""
	}

	resetColor := "\033[0m"
	boldCode := ""
	if bold {
		boldCode = "\033[1m"
	}

	return colorCode + boldCode + text + resetColor
}

func IsValidProxy(input string) bool {
	parts := strings.Split(input, ":")
	if len(parts) != 2 {
		return false
	}

	ip := parts[0]
	portStr := parts[1]

	if net.ParseIP(ip) == nil {
		return false
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	return true
}

func PrintHelp() {
	fmt.Println("Hauditor is a tool for auditing HTTP security headers.")
	fmt.Println("\nUsage:")
	fmt.Printf("  %s [arguments]\n", os.Args[0])
	fmt.Println("\nThe arguments are:")
	fmt.Println("  -t string    Specify the target URL (e.g., domain.com or https://domain.com)")
	fmt.Println("  -f string    Specify the file (e.g., domain.txt)")
	fmt.Println("  -m string    HTTP method (HEAD, GET, POST, PUT, etc.)")
	fmt.Println("  -b string    HTTP request body")
	fmt.Println("  -p string    Specify the proxy URL (e.g., 127.0.0.1:8080)")
	fmt.Println("  -c string    Specify cookies (e.g., \"user_token=g3p21ip21h;\" ")
	fmt.Println("  -r string    Specify headers (e.g., \"Myheader: test\")")
	fmt.Println("  -timeout     Specify connection timeout in seconds (Default 10)")
	fmt.Println("  -j           Output results in JSON format")
	fmt.Println("  -h           Display help")

	fmt.Println("\nExamples:")
	fmt.Printf("  %s -t domain.com\n", os.Args[0])
	fmt.Printf("  %s -t https://domain.com -p 127.0.0.1:8080\n", os.Args[0])
	fmt.Printf("  %s -f domains.txt\n", os.Args[0])
	fmt.Printf("  %s -c \"user_token=hjljkklpo\"\n", os.Args[0])
	fmt.Printf("  %s -r \"Myheader: test\"\n", os.Args[0])
}

func PrintBanner() {

	fmt.Println(Colorize(".__                     .___.__  __                ", "cyan", true))
	fmt.Println(Colorize("|  |__ _____   __ __  __| _/|__|/  |_  ___________ ", "cyan", true))
	fmt.Println(Colorize("|  |  \\__   \\ |  |  \\/ __ | |  \\   __\\/  _ \\_  __ \\", "cyan", true))
	fmt.Println(Colorize("|   Y  \\/ __ \\|  |  / /_/ | |  ||  | (  <_> )  | \\/", "cyan", true))
	fmt.Println(Colorize("|___|  (____  /____/\\____ | |__||__|  \\____/|__|   ", "cyan", true))
	fmt.Println(Colorize("     \\/     \\/           \\/                          ", "cyan", true))
	fmt.Println()

}
