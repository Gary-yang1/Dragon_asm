apt-get update
apt-get install libpcap-dev -y
chmod +x lib/masscan/masscan
chmod +x lib/subfinder/subfinder
chmod +x lib/ob/observer_ward
chmod +x lib/dirscan/dirscan
echo "记得配key"

# ===== embed lib/ into binary =====
rm -rf internal/baiyan/lib
cp -r lib internal/baiyan/lib
go build -o baiyan ./cmd/baiyan/
rm -rf internal/baiyan/lib
