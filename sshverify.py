#!/usr/bin/env python
#-*- coding: utf-8 -*-

import sys
import os
import time
import logging
import socket
import paramiko
from optparse import OptionParser

SSH_TIMEOUT = 8
logger = None

def initLogger(logfile, level=logging.INFO):
    logger = logging.getLogger()
    hdlr = logging.FileHandler(logfile)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(level)
    return logger

def set_paramiko_log(level=logging.FATAL):
    logging.getLogger("paramiko").setLevel(level)

def ssh2(host, port, username, password):
    global logger
    print 'connecting %s:%d' %(host,port)
    print '#############################'
    bufsize = 2048
    output = ''
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port, username, password, timeout=SSH_TIMEOUT)
        chan = ssh.invoke_shell()
        chan.set_combine_stderr(True)
        chan.settimeout(6.0)
        banner = chan.recv(bufsize).strip()
        print '[>',banner,'<]',chan.closed,ssh.get_transport().is_active(),'\n'
        logger.info('%s:%d %r' % (host, port, banner[0:50]))
        ssh.close()
    
        if banner.find('Authorization failed')>=0:
            return False,'AUTH FAIL'
        if banner.find('my name is')>=0:
            return False,'VOIP/PHONE'
        if banner.find('Grandstream')>=0:
            return True,'VOIP/PHONE'
        if banner.find('Last login')>=0 or banner.find('Last unsuccessful login')>=0:
            return True,'LINUX/UNIX'
        if banner.find('smashclp')>=0:
            return True,'IPMI/INSPUR'
        return True,banner.strip()
    except Exception as e:
        print '>>> %s\terror: %s'%(host, str(e))
        logger.info('*ECONN: %s:%d' % (host, port))
        return False,None

# records in infile:
# ip,port,username,password,banner\n
def loadRecords(infile):
    rs = []
    for ln in open(infile):
        fs = ln.strip().split(',',4)
        if len(fs)==5:
            rs.append(fs)
    return rs

def main():
    global logger
    options = OptionParser(usage='%prog [options]', version='1.0.0', description='SshVerify')
    options.add_option('-l', '--logfile', type='string', default='SshVerify.log', help='program log file')
    options.add_option('-i', '--infile', type='string', help='input file')
    options.add_option('-o', '--outfile', type='string', help='output file')
    
    opts, args = options.parse_args()
    logger = initLogger(opts.logfile)
    set_paramiko_log()
    if not opts.infile or not opts.outfile:
        options.print_help()
        sys.exit(-1)
        
    fwo = open(opts.outfile, 'wb')    
    records = loadRecords(opts.infile)
    logger.info('SshVerify started.')

    for host,port,username,password,banner in records:
        if banner=='' or banner.find('IPHONE')>=0:
            try:
                status,banner= ssh2(host,int(port),username,password)
                if status:
                    fwo.write('%s,%s,%s,%s,%s\n'%(host,port,username,password,banner))
                else:
                    logger.info('SKIPPING: %s,%s,%s,%s'%(host,port,username,password))
            except Exception as e:
                logger.warn('*ERR2: %s:%s,reason: %s'% (host,port,str(e)))
        else:
            fwo.write('%s,%s,%s,%s,%s\n'%(host,port,username,password,banner))
            
    fwo.close()
    logger.info('SshVerify done.')
    
if __name__=='__main__':
    main()
