#!/data/data/com.termux/files/usr/bin/bash
pkg install -y git >/dev/null 2>&1
git config user.name "hackproff23-max" ; git config user.email "hackproff23-max@users.noreply.github.com"
[ -d .git ] || git init -b main
git add -A && git commit -m "DNSPRO" 
git remote remove origin 2>/dev/null
git remote add origin https://github.com/hackproff23-max/DNSPRO.git
git push -u origin main --force
