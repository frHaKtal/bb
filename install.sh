#!/bin/bash

# Créer le répertoire tools/ s'il n'existe pas
mkdir -p tools

# Installer les dépendances nécessaires
sudo apt update
sudo apt install -y python3 python3-pip git

# Installer OneForAll
git clone https://github.com/shmilylty/OneForAll.git tools/OneForAll
cd tools/OneForAll
sudo python3 setup.py install
cd -

# Installer GoSpider
GO111MODULE=on go get -u github.com/jaeles-project/gospider

# Installer Hakrawler
GO111MODULE=on go get github.com/hakluke/hakrawler

# Installer SubDomainizer
git clone https://github.com/nsonaniya2010/SubDomainizer.git tools/SubDomainizer

# Installer LinkFinder
git clone https://github.com/GerbenJavado/LinkFinder.git tools/LinkFinder
cd tools/LinkFinder
python3 setup.py install
cd -

# Installer Gau
GO111MODULE=on go get -u github.com/lc/gau

# Installer Waybackurls
GO111MODULE=on go get github.com/tomnomnom/waybackurls

# Installer Naabu
GO111MODULE=on go get -u github.com/projectdiscovery/naabu/cmd/naabu

# Installer Assetfinder
go get -u github.com/tomnomnom/assetfinder

# Installer Sublist3r
git clone https://github.com/aboul3la/Sublist3r.git tools/Sublist3r

# Installer CTFR
git clone https://github.com/UnaPibaGeek/ctfr.git tools/ctfr

# Installer tlsx
go get -u github.com/subfinder/tlsx

# Installer GetSubdomain
go get -u github.com/monkeym4ster/GetSubdomain

# Installer Shosubgo
GO111MODULE=on go get -u github.com/incogbyte/shosubgo/cmd/shosubgo

# Installer Subfinder
GO111MODULE=on go get -u github.com/projectdiscovery/subfinder/v2/cmd/subfinder

# Cloner le script Github Search
git clone https://github.com/gwen001/github-search.git tools/github-search

# Installer Shuffledns
GO111MODULE=on go get -u github.com/projectdiscovery/shuffledns/cmd/shuffledns

# Installer Aquatone
go get github.com/michenriksen/aquatone

# Installer Firefox (si ce n'est pas déjà installé)
sudo apt install -y firefox

# Télécharger le fichier fuzzz.txt pour ffuf
wget https://raw.githubusercontent.com/ffuf/ffuf/master/wordlists/directory-list-2.3-small.txt -O tools/fuzzz.txt

# Assurer les permissions
chmod +x tools/*

echo "Installation terminée!"
