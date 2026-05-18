#!/bin/bash

set -e


BIN_DIR="/usr/sbin"

TMP_DIR="/tmp/ra137_install"

mkdir -p $TMP_DIR

cd $TMP_DIR


echo "[+] Installing dependencies"

apt update -y

apt install -y \
    wget \
    curl \
    unzip \
    git \
    python3 \
    python3-pip \
    jq


download_binary() {

    NAME=$1
    URL=$2
    ARCHIVE=$3
    BINARY=$4

    echo "[+] Installing $NAME"

    wget -q -O $ARCHIVE $URL

    unzip -o $ARCHIVE

    chmod +x $BINARY

    mv $BINARY $BIN_DIR/

}


echo "[+] Installing subfinder"

download_binary \
"subfinder" \
"https://github.com/projectdiscovery/subfinder/releases/download/v2.14.0/subfinder_2.14.0_linux_amd64.zip" \
"subfinder.zip" \
"subfinder"


echo "[+] Installing httpx"

download_binary \
"httpxx" \
"https://github.com/projectdiscovery/httpx/releases/download/v1.9.0/httpx_1.9.0_linux_amd64.zip" \
"httpx.zip" \
"httpx"
echo "......"


echo "[+] Installing dnsx"

download_binary \
"dnsx" \
"https://github.com/projectdiscovery/dnsx/releases/download/v1.2.3/dnsx_1.2.3_linux_amd64.zip" \
"dnsx.zip" \
"dnsx"


echo "[+] Installing nuclei"

download_binary \
"nuclei" \
"https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_linux_amd64.zip" \
"nuclei.zip" \
"nuclei"


echo "[+] Installing gobuster"

wget -q -O gobuster.tar.gz \
"https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_x86_64.tar.gz"

tar -xzf gobuster.tar.gz

chmod +x gobuster

mv gobuster $BIN_DIR/


echo "[+] Installing gow"

wget -q -O gow \
"https://github.com/sensepost/gowitness/releases/download/3.1.1/gowitness-3.1.1-linux-amd64"


chmod +x gow

mv gow $BIN_DIR/


echo "[+] Installing Python libraries"

pip3 install --break-system-packages \
    requests \
    beautifulsoup4 \
    mmh3 \
    cryptography \
    dnspython \
    urllib3 \
    tldextract \
    openai


echo "[+] Installing JARM"

cd /root/RA137/jarm

pip3 install --break-system-packages \
    -r requirements.txt

cd ..


echo "[+] Updating nuclei templates"

nuclei


echo "[+] Cleaning"

rm -rf $TMP_DIR


echo "[+] Installation completed"