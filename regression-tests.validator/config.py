#!/usr/bin/env python
from subprocess import check_output, check_call
from os import chdir, mkdir
from shutil import rmtree

# BASE = 'bad-dnssec.example.net'
BASE = ''
DEPTH = 4
FLAVORS = [
    'ok',
    # 'bogussig',
    'nods',
    # 'sigexpired',
    # 'signotincepted',
    # 'unknownalgorithm'
]

def genzone(name, flavor, depth, conffile):
    if depth > DEPTH:
        return

    if flavor:
        if name:
            myname = '%s.%s' % (flavor, name)
        else:
            myname = flavor
    else:
        myname = name

    f = open('zones/%s.zone' % (myname or 'ROOT'), 'w')
    print myname or 'ROOT'
    print "generating [%s] at depth %s" % (myname, depth)

    f.write("""
$ORIGIN .
%(myname)s   86400   IN SOA ns1.example.com. hostmaster.example.com. 1 3600 3600 3600 3600
%(myname)s   86400   IN NS  %(myname)s
%(myname)s   86400   IN A   127.0.0.127
""" % dict(myname=myname or '.'))

    for next in FLAVORS:
        delegation = genzone(myname, next, depth+1, conffile)
        if delegation:
            f.write('\n'.join(delegation)+'\n')

    f.close()

    chdir("zones")
    ksk = check_output(['ldns-keygen', '-a', 'RSASHA256', '-k', myname or '.']).strip()
    zsk = check_output(['ldns-keygen', '-a', 'RSASHA256', myname or '.']).strip()
    check_call(['ldns-signzone', '-b', '%s.zone' % (myname or 'ROOT'), ksk, zsk])
    chdir("..")

    conffile.write("""
zone "%(zone)s"{
    type master;
    file "./zones/%(fbase)s.zone.signed";
};
""" % dict(zone = myname or '.', fbase = myname or 'ROOT'))

    # check_call(['../pdns/pdnssec', '--config-dir=.', 'set-presigned', myname])

    if myname == '':
        with open('rootDS', 'w') as f:
            f.write(open('zones/%s.ds' % ksk).read().strip().split('\t')[3])

    delegation = ["%(myname)s   86400   IN NS  %(myname)s" % dict(myname=myname or '.'),
                  "%(myname)s   86400   IN A   127.0.0.127" % dict(myname=myname or '.')]

    if flavor != 'nods':
        delegation.append(open('zones/%s.ds' % ksk).read().strip())

    return delegation


if __name__ == '__main__':
    try:
        rmtree('zones')
    except OSError:
        pass
    mkdir('zones')
    with open('pdns.conf', 'w') as f:
        f.write("""
socket-dir=./
launch=bind
bind-dnssec-db=./dnssec.sqlite3
bind-config=./named.conf
""")
    # check_call(['../pdns/pdnssec', '--config-dir=.', 'create-bind-db', 'dnssec.sqlite3'])
    conffile = open('named.conf', 'w')
    genzone(BASE, '', 0, conffile)
    conffile.close()

