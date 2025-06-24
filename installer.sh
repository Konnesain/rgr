#!/bin/bash
mkdir .rgrinstaller
curl --output .rgrinstaller/rgr.tar.gz https://github.com/Konnesain/rgr/releases/latest/rgr.tar.gz
tar -xzvf .rgrinstaller/rgr.tar.gz -C .rgrinstaller
sudo cp -f .rgrinstaller/rgraes.so .rgrinstaller/rgrviginere.so .rgrinstaller/rgrtransposition.so /usr/lib/
sudo cp -f .rgrinstaller/rgr /usr/bin/
rm -rf .rgrinstaller