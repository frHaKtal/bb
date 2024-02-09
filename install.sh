#!/bin/bash

# Créer le répertoire tools/ s'il n'existe pas
mkdir -p tools

# Installer rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Installer les dépendances nécessaires
sudo apt update
sudo apt install -y python3 python3-pip git

# Installer Paramspider
git clone https://github.com/devanshbatham/paramspider tools/paramspider
cd tools/paramspider;python3 setup.py install;cd ../..

# Installer rustscan
git clone https://github.com/RustScan/RustScan.git tools/RustScan
cd RustScan
cargo build --release
sudo cp target/release/rustscan /usr/local/bin/

# Installer OneForAll
git clone https://github.com/shmilylty/OneForAll.git tools/OneForAll
cd tools/OneForAll
sudo python3 setup.py install
cd -

# Installer Uniq
sudo apt-get install coreutils

# Installer GoSpider
GO111MODULE=on go install github.com/jaeles-project/gospider@latest

# Installer Hakrawler
GO111MODULE=on go install github.com/hakluke/hakrawler@latest

# Installer SubDomainizer
git clone https://github.com/nsonaniya2010/SubDomainizer.git tools/SubDomainizer

# Installer LinkFinder
git clone https://github.com/GerbenJavado/LinkFinder.git tools/LinkFinder
cd tools/LinkFinder
python3 setup.py install
cd -

# Installer Gau
GO111MODULE=on go install github.com/lc/gau@latest

# Installer Waybackurls
GO111MODULE=on go install github.com/tomnomnom/waybackurls@latest

# Installer Naabu
GO111MODULE=on go install github.com/projectdiscovery/naabu/cmd/naabu@latest

# Installer Assetfinder
go install github.com/tomnomnom/assetfinder@latest

# Installer Sublist3r
git clone https://github.com/aboul3la/Sublist3r.git tools/Sublist3r

# Installer CTFR
git clone https://github.com/UnaPibaGeek/ctfr.git tools/ctfr

# Installer tlsx
go install github.com/subfinder/tlsx@latest

# Installer GetSubdomain
go install github.com/monkeym4ster/GetSubdomain@latest

# Installer Shosubgo
GO111MODULE=on go install github.com/incogbyte/shosubgo/cmd/shosubgo@latest

# Installer Subfinder
GO111MODULE=on go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Cloner le script Github Search
git clone https://github.com/gwen001/github-search.git tools/github-search

# Installer Shuffledns
GO111MODULE=on go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# Installer Aquatone
go install github.com/michenriksen/aquatone@latest

# Installer Firefox (si ce n'est pas déjà installé)
sudo apt install -y firefox

# Télécharger le fichier fuzzz.txt pour ffuf
wget https://raw.githubusercontent.com/ffuf/ffuf/master/wordlists/directory-list-2.3-small.txt -O tools/fuzzz.txt

# Assurer les permissions
chmod +x tools/*

echo "Installation terminée!"
