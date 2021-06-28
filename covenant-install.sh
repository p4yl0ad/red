#!/usr/bin/bash


rm -rf /opt/Covenant 2>/dev/null
rm -rf /opt/runtime.tar.gz 2>/dev/null

sudo apt remove dotnet* -y
sudo apt remove aspnetcore* -y


wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb

sudo apt-get update -y; \
	sudo apt-get install -y apt-transport-https && \
	sudo apt-get update && \
	sudo apt-get install -y dotnet-sdk-3.1 aspnetcore-runtime-3.1 dotnet-runtime-3.1

git clone --recurse-submodules https://github.com/cobbr/Covenant
cd /opt/Covenant/Covenant
/usr/bin/dotnet clean
/usr/bin/dotnet build
/usr/bin/dotnet run
