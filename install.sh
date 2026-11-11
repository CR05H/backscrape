#!/usr/bin/env bash
# backscrape installer — copies the script onto PATH
set -e
sudo cp backscrape.sh /usr/local/bin/backscrape
sudo chmod +x /usr/local/bin/backscrape
echo "installed: run 'backscrape --help'"
