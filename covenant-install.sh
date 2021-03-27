#!/usr/bin/bash

rm -rf /opt/Covenant 2>/dev/null
rm -rf /opt/runtime.tar.gz 2>/dev/null
#https://dotnet.microsoft.com/download/dotnet/3.1
wget 'https://download.visualstudio.microsoft.com/download/pr/a11a4be1-2a51-4ddc-a23a-56348ea45101/20085ae5fbefd18642babcee279a74e4/aspnetcore-runtime-3.1.13-linux-x64.tar.gz' -O /opt/runtime.tar.gz
mkdir -p $HOME/dotnet && tar zxf /opt/runtime.tar.gz -C $HOME/dotnet
export DOTNET_ROOT=$HOME/dotnet
export PATH=$PATH:$HOME/dotnet
git clone --recurse-submodules https://github.com/cobbr/Covenant
cd Covenant/Covenant
dotnet build
#dornet run
