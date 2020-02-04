#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import traceback
import pickle
import logging
import logging.handlers
import time
import io
# pop/imap/emal
import poplib
import imaplib
import email
import email.policy
import email.header
#import dateutil.tz
import datetime

APPLICATION_NAME = "imapsort"

stdout_fmt = '%(asctime)s %(levelname)s %(name)s - %(message)s'
logger = logging.getLogger(APPLICATION_NAME)

# helpers
def set_logger(quiet, verbose, debug, colorize=True):
    _lvl = logging.INFO + 10*quiet - 10*verbose
    if debug:
        _lvl = logging.DEBUG
    _cformatter = logging.Formatter(stdout_fmt)
    _ch = logging.StreamHandler()
    _ch.setLevel(_lvl)
    _ch.setFormatter(_cformatter)
    logger = logging.getLogger(APPLICATION_NAME)
    logger.setLevel(_lvl)
    logger.addHandler(_ch)

# email
def parse_date(msg):
    m_date = msg['date']
    d_date = email.utils.parsedate_to_datetime(m_date)
    return d_date.astimezone().isoformat()

def parse_message(b: bytes):
    #msg = email.message_from_bytes(b, policy=email.policy.SMTP)
    msg = email.message_from_bytes(b, policy=email.policy.SMTPUTF8)
    date = parse_date(msg)
    subject = msg['subject']
    return (msg, date, subject)

def match_header(header: str, match: str, msg: email.message.EmailMessage)->bool:
    s = email.header.decode_header(msg.get(header))
    return match in s[0]

# imap
def login_imap(host, user, password, port=0, is_tls=False, is_debug=False):
    if is_debug:
        imaplib.Debug = 4
    if is_tls:
        p = port if port else imaplib.IMAP4_SSL_PORT
        M = imaplib.IMAP4_SSL(host, port=p)
    else:
        p = port if port else imaplib.IMAP4_PORT
        M = imaplib.IMAP4(host, port=p)
    if 'AUTH=CRAM-MD5' in M.capabilities:
        typ, data = M.login_cram_md5(user, password)
    else:
        typ, data = M.login(user, password)
    logger.info("{} {}".format(typ, data))
    return M

def logout_imap(M, expunge=False):
    typ, data = M.expunge()
    logger.debug("imap: {} {}".format(typ, data))
    typ, data = M.close()
    logger.debug("imap: {} {}".format(typ, data))
    typ, data = M.logout()
    logger.debug("imap: {} {}".format(typ, data))

def move_mbox(M, uid, dst):
    # copy
    typ, data = M.uid('COPY', uid, dst)
    logger.debug("imap: {} {}".format(typ, data))
    # flag delete
    typ, data = M.uid('STORE', uid , '+FLAGS', '(\Deleted)')
    logger.debug("imap: {} {}".format(typ, data))
    
def process_emails_imap(args):
    # imap login
    M = login_imap(args.mail_server, args.mail_user, args.mail_pass, args.tls, args.debug)
    typ, data = M.list()
    logger.info("list mailboxes")
    for d in data:
        logger.info(d.decode('utf-8'))
    
    # get uids in mailbox (args.imap_src_mbox)
    M.select(args.imap_src_mbox)
    typ, data = M.uid('search', None, "ALL")
    if typ != "OK":
        logger.error("failed to imap search")
    uids = data[0].split()
    logger.info("IMAP server has {} messages in mailbox {}.".format(len(uids), args.imap_src_mbox))
    logger.debug("uids: {}".format(uids))
    
    # return if there are no emails.
    if len(uids) == 0:
        logout_imap(M, False)
        return
    
    try:
        for uid in uids:
            try:
                typ, data = M.uid('fetch', uid, '(RFC822)')
                raw_msg_bytes = data[0][1]
                mail, d, s = parse_message(raw_msg_bytes)
                logger.info("parsed: {}: {}: {}".format(uid, d, s))
                if match_header(args.header_match[0], args.header_match[1], mail):
                    if not args.dry_run:
                      move_mbox(M, uid, args.imap_dst_mbox)
                    logger.info("moved: {}: {}: {}".format(uid, d, s))
            except KeyboardInterrupt:
                raise
            except Exception as e:
                if not args.force:
                    raise
                logger.exception('Exception googleapiclient.errors.HttpError occured. Skip the email.')
                logger.warning('Ignore the exception and continue processing.')
                continue
            #input("Type 'Ctrl+C' if you want to interrupt program.")
    finally:
        logout_imap(M, True)

def main():
    if args.mail_proto == 'IMAP':
        process_emails = process_emails_imap
    else:
        raise Exception("Unknown protocol")
    
    while args.interval:
        try:
            process_emails(args)
            logger.info("waiting interval...")
            time.sleep(args.interval)
        except KeyboardInterrupt:
            sys.exit("Crtl+C pressed. Shutting down.")
    else:
        process_emails(args)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='imapsort sorts your emails on a IMAP-server into destination mailbox.')
    parser.add_argument('--mail-server',  action="store", default=os.getenv("MAIL_SERVER", 'localhost'))
    parser.add_argument('--mail-port',  action="store", type=int, default=os.getenv("MAIL_PORT", 0))
    parser.add_argument('--mail-proto',  action="store", default=os.getenv("MAIL_PROTOCOL", 'IMAP'), choices=['IMAP'])
    parser.add_argument('--mail-user',  action="store", default=os.getenv("MAIL_USER"))
    parser.add_argument('--mail-pass',  action="store", default=os.getenv("MAIL_PASS"))
    parser.add_argument('--imap-src-mbox',  action="store", default=os.getenv("IMAP_SRC_MBOX", "SRC_BOX"), help="source mailbox")
    parser.add_argument('--imap-dst-mbox',  action="store", default=os.getenv("IMAP_DST_MBOX", "DEST_BOX"), help="destination mailbox")
    parser.add_argument('-hm', '--header-match', nargs=2,  action="store", default=['From', 'from@example.com'], metavar=('HEADER', 'MATCH'), help="match keyword")
    parser.add_argument('--dry-run',  action="store_true", help="dry run")
    parser.add_argument('--tls',  action="store_true", help="Enable TLS/SSL for POP3/IMAP protocol")
    parser.add_argument('-i', '--interval', action="store", type=int, default=None, help="Wait interval seconds between import process. Type Ctrl+c if you want stop program.")
    parser.add_argument('-f', '--force', action="store_true", help="Ignore the exception and continue the import process, if used with the -i option.")
    parser.add_argument('-v', '--verbose', action='count', default=0, help="Make the operation more talkative")
    parser.add_argument('-q', '--quiet', action='count', default=0, help="Quiet mode")
    parser.add_argument('-d', '--debug',  action="store_true", help="Enable debug message.")
    args = parser.parse_args()

    # set logger
    set_logger(args.quiet, args.verbose, args.debug)
    if args.debug:
        httplib2.debuglevel = 1 + args.verbose

    logger.debug(args)
    logger.debug('logging level: %s' % logger.getEffectiveLevel())

    main()
