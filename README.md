# imapsort
The imapsort sorts your emails on a IMAP-server into destination mailbox.

## Usage

```shell
export MAIL_SERVER=mail.example.com
export MAIL_USER=foo
export MAIL_PASS=bar
export IMAP_SRC_MBOX=foo
export IMAP_DST_MBOX=bar

python3 imapsort.py --header-match From from@example.com 
```

```
$ python3 imapsort.py -h
usage: imapsort.py [-h] [--mail-server MAIL_SERVER] [--mail-port MAIL_PORT]
                   [--mail-proto {IMAP}] [--mail-user MAIL_USER]
                   [--mail-pass MAIL_PASS] [--imap-src-mbox IMAP_SRC_MBOX]
                   [--imap-dst-mbox IMAP_DST_MBOX] [-hm HEADER MATCH]
                   [--dry-run] [--tls] [-i INTERVAL] [-f] [-v] [-q] [-d]

imapsort sorts your emails on a IMAP-server into destination mailbox.

optional arguments:
  -h, --help            show this help message and exit
  --mail-server MAIL_SERVER
  --mail-port MAIL_PORT
  --mail-proto {IMAP}
  --mail-user MAIL_USER
  --mail-pass MAIL_PASS
  --imap-src-mbox IMAP_SRC_MBOX
                        source mailbox
  --imap-dst-mbox IMAP_DST_MBOX
                        destination mailbox
  -hm HEADER MATCH, --header-match HEADER MATCH
                        match keyword
  --dry-run             dry run
  --tls                 Enable TLS/SSL for POP3/IMAP protocol
  -i INTERVAL, --interval INTERVAL
                        Wait interval seconds between import process. Type
                        Ctrl+c if you want stop program.
  -f, --force           Ignore the exception and continue the import process,
                        if used with the -i option.
  -v, --verbose         Make the operation more talkative
  -q, --quiet           Quiet mode
  -d, --debug           Enable debug message.
```
