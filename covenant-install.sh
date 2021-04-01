#!/usr/bin/bash


rm -rf /opt/Covenant 2>/dev/null
rm -rf /opt/runtime.tar.gz 2>/dev/null

#wget 'https://download.visualstudio.microsoft.com/download/pr/a11a4be1-2a51-4ddc-a23a-56348ea45101/20085ae5fbefd18642babcee279a74e4/aspnetcore-runtime-3.1.13-linux-x64.tar.gz' -O /opt/runtime.tar.gz

sudo git clone --recurse-submodules https://github.com/ZeroPointSecurity/Covenant.git /opt/Covenant

sudo apt remove dotnet* -y
sudo apt remove aspnetcore* -y

wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb

sudo apt-get update -y; \
  sudo apt-get install -y apt-transport-https && \
  sudo apt-get update && \
  sudo apt-get install -y dotnet-sdk-3.1 aspnetcore-runtime-3.1 dotnet-runtime-3.1

cd /opt/Covenant/Covenant
/usr/bin/dotnet clean
/usr/bin/dotnet build
/usr/bin/dotnet run

#/usr/bin/dotnet publish -c Release
#/usr/bin/dotnet /opt/Covenant/Covenant/bin/Release/netcoreapp3.1/Covenant.dll


#mkdir -p $HOME/dotnet && tar zxf /opt/runtime.tar.gz -C $HOME/dotnet

#export DOTNET_ROOT=$HOME/dotnet
#export PATH=$PATH:$HOME/dotnet


#git clone --recurse-submodules https://github.com/cobbr/Covenant -b

#cd Covenant/Covenant
#dotnet build
