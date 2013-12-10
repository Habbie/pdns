#!/usr/bin/env python
from subprocess import check_output, check_call
from os import chdir, mkdir
from shutil import rmtree

# BASE = 'bad-dnssec.example.net'
BASE = ''
DEPTH = 2
FLAVORS = []

for f in ['ok',
          'bogussig',
          'nods',
          'sigexpired',
          'signotincepted',
          'unknownalgorithm']:
    for n in ['nsec1', 'nsec3', 'unsigned']: # NOTE! ldns-sign-special is only special for nsec1
        FLAVORS.append('%s-%s' % (f,n))

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

    issigned = 'unsigned' not in flavor
    if issigned:
        chdir("zones")
        ksk = check_output(['ldns-keygen', '-a', 'RSASHA256', '-k', myname or '.']).strip()
        zsk = check_output(['ldns-keygen', '-a', 'RSASHA256', myname or '.']).strip()
        signflags = []
        if 'nsec3' in flavor:
            signflags.append('-n')
        check_call(['ldns-sign-special']+signflags+['-b', '%s.zone' % (myname or 'ROOT'), ksk, zsk])
        chdir("..")

    conffile.write("""
zone "%(zone)s"{
    type master;
    file "./zones/%(fbase)s.zone%(ext)s";
};
""" % dict(zone = myname or '.', fbase = myname or 'ROOT', ext=['', '.signed'][issigned]))

    # check_call(['../pdns/pdnssec', '--config-dir=.', 'set-presigned', myname])

    if myname == '' and issigned:
        with open('rootDS', 'w') as f:
            f.write(open('zones/%s.ds' % ksk).read().strip().split('\t')[3])

    delegation = ["%(myname)s   86400   IN NS  %(myname)s" % dict(myname=myname or '.'),
                  "%(myname)s   86400   IN A   127.0.0.127" % dict(myname=myname or '.')]

    if 'nods' not in flavor:
        if issigned:
            delegation.append(open('zones/%s.ds' % ksk).read().strip())
        else:
            delegation.append('%s. 86400 IN DS  47718 8 2 f5087548631be05ed8f75bb96f60f77435db56a003a9de0b2a880533ecbcbfee' % myname)

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

