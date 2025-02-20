#!/bin/bash

WHITE='\033[1;37m'
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'

show_logo() {
    echo -e "${RED}                         "
    echo -e "  ===========================  "
    echo -e "       -=(NUCLEAR BOMB)=-      "
    echo -e "  ===========================  "
    echo -e "${GREEN}"
    echo -e "       _.-^^---....,,--        "
    echo -e "   _--                  --_    "
    echo -e "  <                        >)  "
    echo -e "  |                         |  "
    echo -e "   \._                   _./   "
    echo -e "      '''--. . , ; .--'''      "
    echo -e "            | |   |            "
    echo -e "         .-=||  | |=-.         "
    echo -e "         '-=£|  | |£=-'        "
    echo -e "            | |   |            "
    echo -e "      .--'''| |   |'''--.      "
    echo -e "   ./   .-''  |   | ''-.  \.   "
    echo -e "    \.       /  \ /       ./   "
    echo -e "      '''--._____.--'''        "
    echo -e "                               "
    echo -e "${WHITE}                                             "
    echo -e "====================================================="
    echo -e  "    Welcome to the Nuclei-AI-Prompts Framework      "
    echo -e "====================================================="
    echo -e "${NC}"
    echo -e "${WHITE}   Authors:"
    echo -e "DIMOOON (https://github.com/reewardius) - Nuclei-AI-Prompts."
    echo -e "KL3FT3Z (https://github.com/toxy4ny) - Bash-Scripting."
    echo -e "ProjectDiscovery (https://projectdiscovery.io/) - Nuclei, Katana."
    echo -e "${NC}"
}

check_dependencies() {
    echo "checking Docker images and progs..."
    if ! command -v docker &> /dev/null; then
        echo "Docker is not installed. Please install Docker and try again."
        exit 1
    fi
   
    if ! command -v katana &> /dev/null; then
        echo "Katana is not installed. Installation..."
        go install github.com/projectdiscovery/katana/cmd/katana@latest
    fi
   
    if ! command -v nuclei &> /dev/null; then
        echo "Nuuclei is not set. Installation..."
        go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    fi
   
    if ! docker images | grep -q "secsi/getjs"; then
        echo "Uploading a secsi/getjs Docker image..."
        docker pull secsi/getjs
    fi
}

recon() {
    echo "Launching Recon..."
    docker run -v $(pwd):/src projectdiscovery/subfinder:latest -dL /src/domains -silent -o /src/subdomains
    docker run -v $(pwd):/src projectdiscovery/dnsx:latest -l /src/subdomains -t 500 -retry 5 -silent -o /src/dnsx
    docker run -v $(pwd):/src projectdiscovery/naabu:latest -l /src/dnsx -tp 1000 -ec -c 100 -rate 5000 -o /src/alive_ports
    docker run -v $(pwd):/src projectdiscovery/httpx:latest -l /src/alive_ports -t 100 -rl 500 -o /src/targets.txt
}

crawl_links() {
    echo "Scanning active and passive links using Katana..."
    katana -l targets.txt -aff -j -o katana.jsonl
    echo "Scanning JavaScript links..."
    docker run -v $(pwd):/src secsi/getjs --input /src/targets.txt --complete --output /src/js_links
    katana -u targets.txt -ps -em js,json >> js_links
}

fast_info_gathering() {
    echo "Collecting information using Nuclei..."
    nuclei -list targets.txt -ai "Extract page title, detect tech and versions"
    nuclei -list targets.txt -ai "Extract email addresses from web pages"
    nuclei -list targets.txt -ai "Extract all subdomains referenced in web pages"
}

low_hanging_fruit() {
    echo "Search for 'Low Hanging Fruits' vulnerabilities..."
    nuclei -list targets.txt -ai "Find sensitive information in HTML comments (debug notes, API keys, credentials)"
    nuclei -list targets.txt -ai "Find exposed .env files leaking credentials, API keys, and database passwords"
    nuclei -list targets.txt -ai "Find exposed configuration files such as config.json, config.yaml, config.php, application.properties containing API keys and database credentials."
    nuclei -list targets.txt -ai "Find exposed configuration files containing sensitive information such as credentials, API keys, database passwords, and cloud service secrets."  
    nuclei -list targets.txt -ai "Find database configuration files such as database.yml, db_config.php, .pgpass, .my.cnf leaking credentials."  
    nuclei -list targets.txt -ai "Find exposed Docker and Kubernetes configuration files such as docker-compose.yml, kubeconfig, .dockercfg, .docker/config.json containing cloud credentials and secrets."  
    nuclei -list targets.txt -ai "Find exposed SSH keys and configuration files such as id_rsa, authorized_keys, and ssh_config."  
    nuclei -list targets.txt -ai "Find exposed WordPress configuration files (wp-config.php) containing database credentials and authentication secrets."  
    nuclei -list targets.txt -ai "Identify exposed .npmrc and .yarnrc files leaking NPM authentication tokens"
    nuclei -list targets.txt -ai "Identify open directory listings exposing sensitive files"  
    nuclei -list targets.txt -ai "Find exposed .git directories allowing full repo download"
    nuclei -list targets.txt -ai "Find exposed .svn and .hg repositories leaking source code"  
    nuclei -list targets.txt -ai "Identify open FTP servers allowing anonymous access"  
    nuclei -list targets.txt -ai "Find GraphQL endpoints with introspection enabled"  
    nuclei -list targets.txt -ai "Identify exposed .well-known directories revealing sensitive data"  
    nuclei -list targets.txt -ai "Find publicly accessible phpinfo() pages leaking environment details"  
    nuclei -list targets.txt -ai "Find exposed Swagger, Redocly, GraphiQL, and API Blueprint documentation"  
    nuclei -list targets.txt -ai "Identify exposed .vscode and .idea directories leaking developer configs"  
    nuclei -list targets.txt -ai "Detect internal IP addresses (10.x.x.x, 192.168.x.x, etc.) in HTTP responses"  
    nuclei -list targets.txt -ai "Find exposed WordPress debug.log files leaking credentials and error messages"  
    nuclei -list targets.txt -ai "Detect misconfigured CORS allowing wildcard origins ('*')"  
    nuclei -list targets.txt -ai "Find publicly accessible backup and log files (.log, .bak, .sql, .zip, .dump)"  
    nuclei -list targets.txt -ai "Find exposed admin panels with default credentials"
    nuclei -list targets.txt -ai "Identify commonly used API endpoints that expose sensitive user data, returning HTTP status 200 OK."
    nuclei -list targets.txt -ai "Detect web applications running in debug mode, potentially exposing sensitive system information."  
}

advanced_mixed_testing() {
    echo "Advanced mixed tests..."
    nuclei -list targets.txt -ai "Detect debug endpoints revealing system information"  
    nuclei -list targets.txt -ai "Identify test and staging environments exposed to the internet"  
    nuclei -list targets.txt -ai "Find admin login endpoints, filter 404 response code"
    nuclei -list targets.txt -ai "Find misconfigured CORS policies allowing wildcard origins"
    nuclei -list targets.txt -ai "Detect exposed stack traces in error messages"
    nuclei -list targets.txt -ai "Identify default credentials on login pages"
    nuclei -list targets.txt -ai "Find misconfigured Apache/Nginx security headers"  
    nuclei -list targets.txt -ai "Check for APIs allowing unauthenticated access to admin routes"  
    nuclei -list targets.txt -ai "Identify exposed admin panels of popular CMS (WordPress, Joomla, etc.)"
}

sensitive_data_exposure() {
    echo "Search for confidential data leaks..."
    nuclei -list targets.txt -ai "Scan for exposed environment files (.env) containing credentials"
    nuclei -list targets.txt -ai "Find open directory listings and publicly accessible files"
    nuclei -list targets.txt -ai "Detect exposed .git repositories and sensitive files"
    nuclei -list targets.txt -ai "Identify publicly accessible backup and log files (.log, .bak, .sql, .dump)"
    nuclei -list targets.txt -ai "Detect exposed .htaccess and .htpasswd files"
    nuclei -list targets.txt -ai "Check for SSH private keys leaked in web directories"
    nuclei -list targets.txt -ai "Find exposed API keys and secrets in responses and URLs"
    nuclei -list targets.txt -ai "Identify API endpoints leaking sensitive data"
    nuclei -list targets.txt -ai "Find leaked database credentials in JavaScript files"
    nuclei -list targets.txt -ai "Scan for hardcoded credentials in source code comments"
    nuclei -list targets.txt -ai "Identify sensitive endpoints leaking personal or internal data"
    nuclei -list targets.txt -ai "Detect vulnerable API endpoints exposing user input or sensitive information"
    nuclei -list targets.txt -ai "Find exposed server status pages (e.g., phpinfo, server-status)"
    nuclei -list targets.txt -ai "Identify sensitive configuration files (.env, .config, application.properties, settings.py)"
    nuclei -list targets.txt -ai "Scan for information leaks in HTTP responses and headers"
}

sensitive_data_exposure_js() {
    echo "Scan for leaks of confidential data in JavaScript files..."
    local commands=(
        "Analyze JavaScript code for security vulnerabilities (XSS, CSRF, CORS misconfigurations, Clickjacking)"
        "Perform a full deep JavaScript security audit: API keys, secrets, internal endpoints, debug logs, authentication tokens, and misconfigurations"
        "Find hardcoded API keys, JWT tokens, OAuth credentials, and authentication secrets in JavaScript"
        "Identify hardcoded cloud service credentials (AWS, GCP, Azure) in JavaScript files"
        "Find internal API endpoints (REST, GraphQL, WebSockets) hidden in JavaScript files"
        "Detect API keys, JWT tokens, and passwords in JavaScript files"
        "Find AWS, Google Cloud, and Azure API keys exposed in JavaScript"
        "Detect OAuth, Facebook, Twitter, and Google API tokens in JavaScript files"
        "Find Firebase, MongoDB, and Elasticsearch credentials in JavaScript"
        "Detect hardcoded JWT tokens and secrets in JavaScript files"
        "Identify exposed payment API keys for Stripe, PayPal, and Square in JavaScript files"
        "Find debugging logs, internal API endpoints, and test credentials in JavaScript"
        "Detect corporate email addresses, internal contacts and internal resource in JavaScript files"
        "Find exposed JavaScript source maps (.map files) revealing original source code"
    )

    for cmd in "${commands[@]}"; do
        docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "$cmd"
    done
}

sql_injection() {
    echo "Search for SQL Injection vulnerabilities..."
    local commands=(
        "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting SQL Injection vulnerabilities with pre-conditions."
        "Detect SQL error messages indicating SQL injection vulnerabilities"
        "Detect SQL errors in response when injecting common payloads into GET and POST requests"
        "Find SQL injection in 'id', 'user', 'product', 'category', 'page' parameters"
        "Scan for blind SQL injection in 's', 'search', 'query', 'sort', 'filter' GET/POST parameters"
        "Scan for time based SQL injection in all parameters"
        "Identify SQL injection in API endpoints using JSON payloads"
        "Check for SQL injection via HTTP headers (User-Agent, Referer, X-Forwarded-For, X-Forwarded-Host)"
    )

    for cmd in "${commands[@]}"; do
        nuclei -list katana.jsonl -im jsonl -ai "$cmd"
    done
}

cross_site_scripting() {
    echo "Search for XSS vulnerabilities..."
    local commands=(
        "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting XSS vulnerabilities (Reflected, Stored, and DOM-based) with pre-conditions."
        "Find reflected XSS in 'q', 'search', 's', 'redirect', 'next', 'return', 'url' parameters"
        "Find stored XSS in all parameters"
        "Identify stored XSS in comment fields, usernames, profile descriptions"
        "Detect DOM-based XSS in JavaScript variables using common sources like location.href"
        "Scan for XSS vulnerabilities in AJAX endpoints"
        "Check for JSON-based XSS via API responses"
        "Identify reflected cross-site scripting (XSS) vulnerabilities"
    )

    for cmd in "${commands[@]}"; do
        nuclei -list katana.jsonl -im jsonl -ai "$cmd"
    done
}

server_side_request_forgery() {
    echo "Search for SSRF vulnerabilities..."
    local commands=(
        "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting SSRF vulnerabilities with pre-conditions."
        "Find SSRF vulnerabilities in web applications"
        "Identify SSRF vulnerabilities in query parameters"
        "Identify SSRF vulnerabilities in most common parameters"
        "Find SSRF in 'url', 'link', 'redirect', 'next', 'feed', 'callback' parameters"
        "Detect SSRF by injecting internal IP ranges (127.0.0.1, 169.254.169.254)"
        "Identify SSRF in API requests that fetch external resources"
        "Scan for blind SSRF by injecting webhooks and external DNS resolver payloads"
    )

    for cmd in "${commands[@]}"; do
        nuclei -list katana.jsonl -im jsonl -ai "$cmd"
    done
}

file_inclusions() {
    echo "Search for LFI/RFI vulnerabilities..."
    local commands=(
        "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting LFI/RFI vulnerabilities with pre-conditions."
        "Find LFI in 'file', 'path', 'template', 'inc', 'lang', 'page' parameters"
        "Detect RFI by injecting external URLs into 'file' and 'load' parameters"
        "Identify LFI using common payloads (/etc/passwd, ../../etc/passwd, php://filter, php://input)"
        "Check for LFI in error messages exposing full file paths"
    )

    for cmd in "${commands[@]}"; do
        nuclei -list katana.jsonl -im jsonl -ai "$cmd"
    done
}

command_injection() {
    echo "Search for Command Injection (RCE)..."
    local commands=(
        "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting Remote Code Execution (Command Injection) vulnerabilities with pre-conditions."
        "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting Remote Code Execution (RCE) vulnerabilities on Linux and Windows."
        "Detect command injection in 'cmd', 'exec', 'ping', 'query', 'shell' parameters"
        "Scan for OS command injection via HTTP headers (X-Forwarded-For, X-Forwarded-Host, User-Agent, Referer)"
        "Identify RCE vulnerabilities in file upload functionalities"
    )

    for cmd in "${commands[@]}"; do
        nuclei -list katana.jsonl -im jsonl -ai "$cmd"
    done
}

xml_external_entity() {
    echo "Search for XXE vulnerabilities..."
    nuclei -list katana.jsonl -im jsonl -ai "Perform fuzzing on all XML-based inputs using DSL, focusing on detecting XXE vulnerabilities with pre-conditions."
}

host_header_injection() {
    echo "Search for vulnerabilities Host Header Injection..."
    nuclei -l targets.txt -ai "Detect Host Header Injection"
}

cloud_security_issues() {
    echo "Search for vulnerabilities Cloud Security Issues..."
    local commands=(
        "Detect open Docker API endpoints allowing remote access"
        "Detect exposed Kubernetes API servers allowing unauthenticated access"
        "Find open Kubernetes Dashboard instances with weak or no authentication"
        "Detect exposed Kubernetes dashboards and APIs"
        "Scan for cloud metadata endpoints accessible externally"
        "Detect AWS S3, GCP, Azure buckets in response, and scan this cloud storage buckets (AWS S3, GCP, Azure) for misconfigurations (read, write ACL, public access, etc)"
        "Detect Azure Storage Account keys exposed in responses, minimize false positive"
        "Detect AWS keys exposed in responses and write extractors, minimize false positive"
        "Detect GCP keys exposed in responses and write extractors, minimize false positive"
    )

    for cmd in "${commands[@]}"; do
        nuclei -list targets.txt -ai "$cmd"
    done
}

web_cache_poisoning() {
    echo "Search for vulnerabilities Web Cache Poisoning..."
    local commands=(
        "Find web cache poisoning via 'Host', 'X-Forwarded-Host' and'X-Forwarded-For' headers, provide additional vulnerability checking (second/third request)"
        "Detect cache poisoning through 'X-Original-URL' and 'X-Rewrite-URL' headers, provide additional vulnerability checking (second/third request)"
        "Identify cache poisoning by injecting payloads in 'Referer' and 'User-Agent', provide additional vulnerability checking (second/third request)"
        "Scan for cache poisoning via malformed HTTP headers, provide additional vulnerability checking (second/third request)"
        "Detect cache poisoning vulnerabilities on Fastly and Cloudflare, provide additional vulnerability checking (second/third request)"
        "Find misconfigured Varnish caching rules exposing private data, provide additional vulnerability checking (second/third request)"
        "Identify Squid proxy cache poisoning vulnerability, provide additional vulnerability checking (second/third request)"
    )

    for cmd in "${commands[@]}"; do
        nuclei -list targets.txt -ai "$cmd"
    done
}

print_help() {
    echo ""
    echo " Possible commands:"
    echo " help - Displays a list of available commands and their descriptions."
    echo " recon - Performing Recon using the ProjectDiscovery program."
    echo " crawl - Scanning and collecting active and passive links."
    echo " info - Quick collection of information using Nuclei."
    echo " low_hang - Search for vulnerabilities of 'Low Hanging Fruits'."
    echo " advanced - Enabling advanced testing."
    echo " sensitive - Search for leaks of confidential information."
    echo " sensitive-js - Scanning for leaks of confidential data in JavaScript files."
    echo " sql-injection - Scanning for SQL Injection."
    echo " xss - Search for Cross-Site Scripting (XSS) vulnerabilities."
    echo " ssrf - Server-Side Request Forgery (SSRF) vulnerability search."
    echo " lfi-rfi - Search for Local & Remote File Inclusion (LFI/RFI) vulnerabilities."
    echo " rce - Command Injection (RCE) vulnerability Search."
    echo " xxe - Search for XML External Entity (XXE) vulnerabilities."
    echo " host-header - Search for vulnerabilities Host Header Injection."
    echo " cloud - Search for vulnerabilities Cloud Security Issues."
    echo " cache - Search for vulnerabilities Web Cache Poisoning."
    echo " exit - Shutdown of the program."
    echo ""
}

main() {
    show_logo
    check_dependencies
    
    while true; do
        echo ""
        echo "Enter the command to execute (help - print help):"
        read -p "(<>) " command
        case $command in
            recon)
                recon
                ;;
            crawl)
                crawl_links
                ;;
            info)
                fast_info_gathering
                ;;
            low_hang)
                low_hanging_fruit
                ;;
            advanced)
                advanced_mixed_testing
                ;;
            sensitive)
                sensitive_data_exposure
                ;;
            sensitive-js)
                sensitive_data_exposure_js
                ;;
            sql-injection)
                sql_injection
                ;;
            xss)
                cross_site_scripting
                ;;
            ssrf)
                server_side_request_forgery
                ;;
            lfi-rfi)
                file_inclusions
                ;;
            rce)
                command_injection
                ;;
            xxe)
                xml_external_entity
                ;;
            host-header)
                host_header_injection
                ;;
            cloud)
                cloud_security_issues
                ;;
            cache)
                web_cache_poisoning
                ;;
            help)
                print_help
                ;;
            exit)
                echo "Bye-Bye."
                break
                ;;
            *)
                echo "The command was not recognized. Please enter 'help' to get a list of commands."
                ;;
        esac
    done
}

main 