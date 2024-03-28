#!/bin/bash

install_tools() {

    mkdir -p tools

    # Install OneForAll
    git clone https://github.com/shmilylty/OneForAll.git tools/OneForAll
    cd tools/OneForAll
    pip3 install -r requirements.txt
    cd ../

    # Install dnsx
    GO111MODULE=on go get -u -v github.com/projectdiscovery/dnsx/cmd/dnsx

    # Install Naabu
    GO111MODULE=on go get -u -v github.com/projectdiscovery/naabu/v2/cmd/naabu

    # Install gospider
    go get -u github.com/jaeles-project/gospider

    # Install Hakrawler
    go get github.com/hakluke/hakrawler

    # Install SubDomainizer
    git clone https://github.com/nsonaniya2010/SubDomainizer.git tools/SubDomainizer

    # Install LinkFinder
    git clone https://github.com/GerbenJavado/LinkFinder.git tools/LinkFinder
    pip3 install -r tools/LinkFinder/requirements.txt

    # Install Gau
    go get -u github.com/lc/gau

    # Install Waybackurls
    go get -u github.com/tomnomnom/waybackurls

    # Install Rustscan
    mkdir -p tools/rustscan
    wget https://github.com/RustScan/RustScan/releases/download/2.0.0/rustscan_2.0.0_amd64.deb -O tools/rustscan/rustscan_2.0.0_amd64.deb
    sudo dpkg -i tools/rustscan/rustscan_2.0.0_amd64.deb

    # Install Ffuf
    go get -u github.com/ffuf/ffuf

    # Install Aquatone
    go get github.com/michenriksen/aquatone

    # Install assetfinder
    go get -u github.com/tomnomnom/assetfinder

    # Install getsubdomain
    git clone https://github.com/aboul3la/Sublist3r.git tools/Sublist3r

    # Install shosubgo
    go get -u github.com/netevert/shosubgo

    # Install shuffledns
    GO111MODULE=on go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns

    # Install Subfinder
    GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder

    # Install github-subdomains
    git clone https://github.com/gwen001/github-search.git tools/github-search

    # Install tlsx
    go get -u github.com/tomnomnom/tlsx

    # Install httpx
    go get -u github.com/projectdiscovery/httpx/cmd/httpx

    # Install netlas
    go get -u github.com/netlase/netlas/cmd/netlas

    # Install sponge
    sudo apt -y install moreutils

    # Install urldedupe
    git clone https://github.com/P1kachu/urldedupe.git tools/urldedupe
    cd tools/urldedupe
    make
    cd ../../

}

install_tools
