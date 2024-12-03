#!/bin/bash 

# Gerekli paketlerin kontrolü (iwlist ve nmap)
check_packages() {
    if ! command -v iwlist &> /dev/null; then
        echo "iwlist yüklü değil. Lütfen sudo apt install wireless-tools ile yükleyin."
        exit 1
    fi

    if ! command -v nmap &> /dev/null; then
        echo "nmap yüklü değil. Lütfen sudo apt install nmap ile yükleyin."
        exit 1
    fi
}

# Wi-Fi ağlarını tarama ve BSSID ile MAC adreslerini listeleme
scan_network() {
    echo "[*] Wi-Fi ağlarını tarıyorum..."
    iwlist wlan0 scan | grep -E "Cell|Address|ESSID" | awk '
    BEGIN {idx=1}
    /Cell/ {cell=idx++}
    /Address/ {bssid=$5}
    /ESSID/ {ssid=$2}
    {if (bssid != "" && ssid != "") print "BSSID: " bssid ", MAC Address: " $5 ", SSID: " ssid}
    '
}

# Ağdaki cihazları tarama
get_devices_in_network() {
    target_ip=$1
    echo "[*] $target_ip ağındaki cihazları tarıyorum..."
    nmap -sn $target_ip | grep "Nmap scan report" | awk '{print $5}' | while read ip; do
        echo "[*] Cihaz bulundu: $ip"
    done
}

# Seçilen cihazın portlarını tarama
scan_ports() {
    device_ip=$1
    echo "[*] $device_ip cihazındaki açık portları tarıyorum..."
    nmap -p- $device_ip
}

# Ana fonksiyon
main() {
    check_packages

    # Wi-Fi ağlarını tara
    scan_network

    # Kullanıcıdan BSSID girisi yapmasını iste
    echo "[*] Lütfen taradığınız ağlardan bir BSSID girin (örneğin: 98:F0:83:51:42:24):"
    read bssid
    echo "[*] Seçilen BSSID: $bssid"

    # Ağ IP adresi girisi
    echo "[*] Lütfen taramak için ağ IP adresini (örneğin: 192.168.1.0/24) girin:"
    read target_ip

    # Cihazları tarama
    get_devices_in_network $target_ip

    # Cihaz IP adresi girisi
    echo "[*] Port taraması yapmak için bir cihaz IP adresini girin:"
    read device_ip

    # Port taraması yap
    scan_ports $device_ip
}

# Scripti çalıştır
main
