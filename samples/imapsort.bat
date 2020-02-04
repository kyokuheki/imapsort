@echo off
chcp 65001

set MAIL_SERVER=mail.example.com
set MAIL_USER=foo
set MAIL_PASS=bar
set IMAP_SRC_MBOX=INBOX
set IMAP_DST_MBOX=FILTERED

cd /d %~dp0

:loop
  python.exe imapsort.py --move -f %*
  timeout 300
goto :loop
