#!/bin/bash
mkdir .rgrinstaller
curl -Ls --output .rgrinstaller/rgr.tar.gz https://github.com/Konnesain/rgr/releases/latest/download/rgr.tar.gz
tar -xzf .rgrinstaller/rgr.tar.gz -C .rgrinstaller
sudo cp -f .rgrinstaller/rgraes.so .rgrinstaller/rgrviginere.so .rgrinstaller/rgrtransposition.so /usr/lib/
sudo cp -f .rgrinstaller/RGREncryption /usr/bin/
rm -rf .rgrinstaller