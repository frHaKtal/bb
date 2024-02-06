#!/bin/bash

###ajouter un scan rustscan => rustscan -a 10.10.253.28 --ulimit 5000 -- -A
github_key=""

vuln_scan() {


    run() {
     ##spf record
     echo -e "[!]""\E[33m Please wait scan spf record...\E[0m"
     cc=$(echo $subdomain| sed 's/^https:\/\/\|http:\/\///' | awk -F'.' '{if (NF > 2) sub($1"\\.", ""); print}')
     curl -s https://www.kitterman.com/spf/getspf3.py\?serial\=fred12\&domain\=$cc | grep --color=auto "No valid SPF record found." && echo -e "[!]\E[31m $subdomain \E[0m" || echo -e "[●]""\E[31m SPF recond ok...  -  [$cc✔]\E[0m"
    }

    if [[ -n $file ]]; then
             while IFS= read -r subdomain; do
                     run $subdomain
             done < "$file"
    else
             subdomain=$domain
             run $subdomain
             #echo -e "[●]""\E[31m Discovery js/link completed..\E[0m result in bb/js_link.txt"
             #cat "bb/js_link.txt" | urldedupe | sponge bb/js_link.txt
    fi

}


jsdisco() {


    run() {
          echo -e "\n"$subdomain >> js_link.txt
          echo -e "[●]""\E[31m Searching js/link...  -  [gospider✔]\E[0m"
          echo -e "\n###############[ GoSpider ]###############" >> js_link.txt
          tools/gospider -s "$(echo $subdomain | httpx --silent)" -c 10 -d 1 >> js_link.txt
          echo -e "[●]""\E[31m Searching js/link...  -  [hakrawler✔]\E[0m"
          echo -e "\n###############[ Hakrawler ]###############" >> js_link.txt
          echo "$subdomain" | httpx --silent |  hakrawler -subs -d 3 -u >> js_link.txt
          echo -e "[●]""\E[31m Searching js/link...  -  [subdomainizer✔]\E[0m"
          echo -e "\n###############[ SubDomainizer ]###############" >> js_link.txt
          python3 tools/SubDomainizer/SubDomainizer.py -u "$subdomain" >> js_link.txt
          echo -e "[●]""\E[31m Searching js/link...  -  [linkfinder✔]\E[0m"
          echo -e "\n###############[ Linkfinder ]###############" >> js_link.txt
          python3 tools/LinkFinder/linkfinder.py -i "$(echo $subdomain | httpx --silent)" -d -o cli >> js_link.txt
          echo -e "[●]""\E[31m Searching js/link...  -  [gau✔]\E[0m"
          echo -e "\n###############[ Gau ]###############" >> js_link.txt
          tools/gau "$subdomain" >> js_link.txt
          echo -e "[●]""\E[31m Searching js/link...  -  [waybackurls✔]\E[0m"
          echo -e "\n###############[ Waybackurls ]###############" >> js_link.txt
          tools/waybackurls "$subdomain" >> js_link.txt

    }

    echo -e "[!]""\E[33m Please wait js/link discovery...\E[0m"
    if [[ -n $file ]]; then
             while IFS= read -r subdomain; do
                     run $subdomain
             done < "$file"
    else
             subdomain=$domain
             run $subdomain
             echo -e "[●]""\E[31m Discovery js/link completed..\E[0m result in js_link.txt"
             cat "js_link.txt" | tools/urldedupe | tools/sponge js_link.txt
    fi
}


scan_naabu() {

        if [[ -n $file ]]; then
              domain_wild=$(cat "$file" | sed -n 's/\*\.//p')
                     echo -e "[!]""\E[31m Please wait scan port [naabu✔]\E[0m" "$subdomain"
                     tools/naabu -list "$file" -top-ports 100 -c 30 -rate 150 -timeout 5000 -silent | awk -F':' '{domains[$1] = domains[$1] "," $2} END {for (domain in domains) print domain ":" substr(domains[domain], 2)}' > naabu_scan.txt
        else
              subdomain=$domain
              echo -e "[!]""\E[31m Please wait scan port [naabu✔]\E[0m"
              tools/naabu $subdomain -top-ports 100 -c 30 -rate 150 -timeout 5000 -silent | awk -F':' '{domains[$1] = domains[$1] "," $2} END {for (domain in domains) print domain ":" substr(domains[domain], 2)}' > naabu_scan.txt
        fi

    echo -e "[●]""\E[31m Scan completed for Subdomain discovery\E[0m result in naabu_scan.txt\E[0m"

}

domain_wildcard() {

    if  grep '\*.' "$1"; then
        subdomain_discovery $file
    else
        echo -e "[!]""\E[31m No wildcard in $file\E[0m"
    fi
}


fuzzing_ffuf() {

echo -e "[!]""\E[33m Please wait fuzzing with ffuf...\E[0m"

        if [[ -n $file ]]; then
                while IFS= read -r link; do
                    url=$(echo $link | httpx -silent)
                    if [ -n "$url" ]; then
                         tools/ffuf -w fuzzz.txt -e .html,.php,.git,.yaml,.conf,.cnf,.config,.gz,.env,.log,.db,.mysql,.bak,.asp,.aspx,.txt,.conf,.sql,.json,.yml,.pdf -p 0.05 -recursion -recursion-depth 2 -t 30 -timeout 5 -ac -mc 200,204 -u "$url"/FUZZ
                    fi
                done < "$file"
       else
                tools/ffuf -w fuzzz.txt -e .html,.php,.git,.yaml,.conf,.cnf,.config,.gz,.env,.log,.db,.mysql,.bak,.asp,.aspx,.txt,.conf,.sql,.json,.yml,.pdf -p 0.05 -recursion -recursion-depth 2 -t 30 -timeout 5 -ac -mc 200,204 -u "$1"/FUZZ
       fi
}


screenshots() {

    echo -e "[!]""\E[33m Please wait Screenshots file scope with Aquatone...\E[0m"
    cat $file|tools/httpx --silent|tools/aquatone --silent --out bb/
    sudo firefox aquatone_report.html

}


subdomain_discovery() {

   run() {
            echo -e "[!]""\E[33m Please wait while scanning...\E[0m"
            echo -e "[●]""\E[31m Subdomain Scanning is in progress: Scanning subdomains of \E[0m""$subdomain"
            python3 tools/OneForAll/oneforall.py --target "$subdomain" run > /dev/null 2>&1 && cut -d',' -f6 tools/OneForAll/results/"$subdomain".csv >> subdomain.txt && rm -rf tools/OneForAll/results/"$subdomain".csv
            echo -e "[●]""\E[31m Subdomain Scanned  -  [oneforall✔]\E[0m"
            tools/netlas search -d domain -i domain domain:"*.""$subdomain" -f json | grep -oE '([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+"$subdomain"' >> subdomain.txt
            echo -e "[●]""\E[31m Subdomain Scanned  -  [netlas✔]\E[0m"
            tools/sublist3r -d "$subdomain" -t 50 -n >> subdomain.txt
            echo -e "[●]""\E[31m Subdomain Scanned  -  [sublist3r✔]\E[0m"
            python3 tools/ctfr/ctfr.py -d "$subdomain" >> subdomain.txt
            echo -e "[●]""\E[31m Subdomain Scanned  -  [ctfr✔]\E[0m"
            tools/tlsx -san -cn -silent -ro -host "$subdomain" >> subdomain.txt
            echo -e "[●]""\E[31m Subdomain Scanned  -  [tlsx✔]\E[0m"
            tools/assetfinder --subs-only "$subdomain" >> subdomain.txt
            echo -e "[●]""\E[31m Subdomain Scanned  -  [assetfinder✔]\E[0m"
            tools/gau --subs "$subdomain" | cut -d / -f 3 | sort -u >> subdomain.txt
            echo -e "[●]""\E[31m Subdomain Scanned  -  [gau✔]\E[0m"
            tools/getsubdomain "$subdomain" >> subdomain.txt
            echo -e "[●]""\E[31m Subdomain Scanned  -  [getsubdomain✔]\E[0m"
            tools/shosubgo -d "$subdomain" -s 0ZRNnWDIgXCPmRAHoVb2smfVQzAeNgkm >> subdomain.txt
            echo -e "[●]""\E[31m Subdomain Scanned  -  [shosubgo✔]\E[0m"
            tools/subfinder -d "$subdomain" -nc -timeout 5 -t 30 -silent -all >> subdomain.txt
            echo -e "[●]""\E[31m Subdomain Scanned  -  [subfinder✔]\E[0m"
            python3 tools/github-search/github-subdomains.py -d "$subdomain" -t "$github_key" >> subdomain.txt
            echo -e "[●]""\E[31m Subdomain Scanned  -  [github-search✔]\E[0m"
            tools/shuffledns -silent -d "$subdomain" -w tools/all.txt -r tools/resolvers.txt >> subdomain.txt
            echo -e "[●]""\E[31m Subdomain Scanned  -  [shuffledns✔]\E[0m"

   }

        if [[ -n $file ]]; then
              domain_wild=$(cat "$file" | sed -n 's/\*\.//p')
              while IFS= read -r subdomain; do
                  if [ -n "$subdomain" ]; then
                     run $subdomain
                  fi
              done <<< "$domain_wild"
              echo -e "[●]""\E[31m Scan completed for Subdomain discovery\E[0m result in bb/subdomain.txt and added to ""$file""\E[33m    Total: \E[0m" $(cat subdomain.txt|wc -l)
        else
              subdomain=$domain
              run $subdomain
              echo -e "[●]""\E[31m Scan completed for Subdomain discovery\E[0m result in bb/subdomain.txt\E[33m    Total: \E[0m" $(cat subdomain.txt|wc -l)
        fi

   # grep -oE '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' bb/subdomain.txt | sort | uniq | sponge bb/subdomain.txt
   # grep -oE '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' bb/subdomain.txt | sort | uniq >> $file
   # grep -vE '\*' $file | sponge $file
}

show_help() {
  echo "Usage: $0 <module> [-f <file>] [-d <domain>]"
  echo "Modules disponibles: domdisco, fuzz, screenshots, jsdisco, vulnscan, scanport"
  echo "Options:"
  echo "  -f <file>    Spécifie un fichier"
  echo "  -d <domain>  Spécifie un domaine"
  exit 1
}

show_modules() {
  echo "Modules disponibles: domdisco, fuzz, screenshots, jsdisco, vulnscan, scanport"
  exit 1
}

if [ "$#" -eq 0 ]; then
  show_help
fi

module="$1"
shift  # Décaler pour permettre à getopts de traiter les options

case "$module" in
  domdisco|fuzz|screenshots|jsdisco|vulnscan|scanport)
    while getopts ":f:d:" opt; do
      case $opt in
        f)
          file="$OPTARG"
          ;;
        d)
          domain="$OPTARG"
          use_option=true
          ;;
        \?)
          echo "Option invalide: -$OPTARG" >&2
          exit 1
          ;;
        :)
          echo "L'option -$OPTARG nécessite un argument." >&2
          exit 1
          ;;
      esac
    done

    if [ -z "$file" ] && [ -z "$use_option" ]; then
      echo "L'option -f (file) ou -d (domain) est requise."
      show_help
    fi

    case "$module" in
      domdisco)
        if [[ -n $file ]]; then
              domain_wildcard $file
        else
              subdomain_discovery $domain
        fi
        ;;
      fuzz)
        if [[ -n $file ]]; then
              fuzzing_ffuf $file
        else
              fuzzing_ffuf $domain
        fi
        ;;
      screenshots)
        screenshots $file
        ;;
      jsdisco)
        if [[ -n $file ]]; then
              jsdisco $file
        else
              jsdisco $domain
        fi

        ;;
      vulnscan)
        if [[ -n $file ]]; then
              vuln_scan $file
        else
              vuln_scan $domain
        fi

        ;;
      scanport)
        scan_naabu $file
        ;;
    esac
    ;;

  -h|--help)
    show_help
    ;;

  -l|--list-modules)
    show_modules
    ;;

  *)
    echo "Module non reconnu: $module"
    show_modules
    ;;
esac
