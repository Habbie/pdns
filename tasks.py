from invoke import task
from invoke.exceptions import UnexpectedExit

import sys

@task
def apt_fresh(c):
    c.sudo('apt-get update')
    c.sudo('apt-get dist-upgrade')

@task
def install_clang(c):
    """
    install clang-11 and llvm-11
    """
    c.sudo('apt-get -qq -y --no-install-recommends install clang-11 llvm-11')

@task
def install_clang_runtime(c):
    # this gives us the symbolizer, for symbols in asan/ubsan traces
    c.sudo('apt-get -qq -y --no-install-recommends install clang-11')

@task
def install_auth_build_deps(c):
    c.sudo('apt-get install -qq -y --no-install-recommends \
                autoconf \
                automake \
                bison \
                bzip2 \
                curl \
                default-libmysqlclient-dev \
                flex \
                g++ \
                git \
                libboost-all-dev \
                libcdb-dev \
                libcurl4-openssl-dev \
                libgeoip-dev \
                libkrb5-dev \
                libldap2-dev \
                liblmdb-dev \
                libluajit-5.1-dev \
                libmaxminddb-dev \
                libp11-kit-dev \
                libpq-dev \
                libsodium-dev \
                libsqlite3-dev \
                libssl-dev \
                libsystemd-dev \
                libtool \
                libyaml-cpp-dev \
                libzmq3-dev \
                make \
                pkg-config \
                python3-venv \
                ragel \
                ruby-bundler \
                ruby-dev \
                sqlite3 \
                systemd \
                unixodbc-dev \
                wget')

auth_backend_test_deps = dict(
    gsqlite3=['sqlite3'],
    gmysql=['default-libmysqlclient-dev'],
    gpgsql=['libpq-dev'],
)

def setup_authbind(c):
    c.sudo('touch /etc/authbind/byport/53')
    c.sudo('chmod 755 /etc/authbind/byport/53')

@task(help={'backend': 'Backend to install test deps for, e.g. gsqlite3; can be repeated'}, iterable=['backend'], optional=['backend'])
def install_auth_test_deps(c, backend): # FIXME: rename this, we do way more than apt-get
    extra=[]
    for b in backend:
        extra.extend(auth_backend_test_deps[b])
    c.sudo('apt-get -y -qq install \
                authbind \
                bc \
                bind9utils \
                build-essential libsqlite3-dev libzmq3-dev \
                curl \
                default-jre-headless \
                dnsutils \
                gawk \
                git \
                ldnsutils \
                libnet-dns-perl \
                pdns-recursor \
                socat \
                unbound-host \
                            default-libmysqlclient-dev \
            libboost-all-dev \
            libcdb1 \
            libcurl4 \
            libgeoip1 \
            libkrb5-3 \
            libldap-2.4-2 \
            liblmdb0 \
            libluajit-5.1-2 \
            libmaxminddb0 \
            libp11-kit0 \
            libpq5 \
            libsodium23 \
            libssl1.1 \
            libsystemd0 \
            libyaml-cpp0.6 \
            softhsm2 \
            unixodbc wget ' + ' '.join(extra))

    c.run('chmod +x /opt/pdns-auth/bin/*')
    # c.run('''if [ ! -e $HOME/bin/jdnssec-verifyzone ]; then
    #               wget https://github.com/dblacka/jdnssec-tools/releases/download/0.14/jdnssec-tools-0.14.tar.gz
    #               tar xfz jdnssec-tools-0.14.tar.gz -C $HOME
    #               rm jdnssec-tools-0.14.tar.gz
    #          fi
    #          echo 'export PATH=$HOME/jdnssec-tools-0.14/bin:$PATH' >> $BASH_ENV''')  # FIXME: why did this fail with no error?
    c.run('touch regression-tests/tests/verify-dnssec-zone/allow-missing') # FIXME: can this go?
    # FIXME we need to start a background recursor here for some tests
    setup_authbind()

@task
def install_rec_test_deps(c): # FIXME: rename this, we do way more than apt-get
    c.sudo('apt-get --no-install-recommends install -qq -y python3-venv python3-dev default-libmysqlclient-dev libpq-dev pdns-tools libluajit-5.1-2 \
              libboost-all-dev \
              libcap2 \
              libssl1.1 \
              libsystemd0 \
              libsodium23 \
              libfstrm0 \
              libsnmp30')
    setup_authbind()

@task
def install_dnsdist_test_deps(c): # FIXME: rename this, we do way more than apt-get
    c.sudo('apt-get install -qq -y \
              libluajit-5.1-2 \
              libboost-all-dev \
              libcap2 \
              libcdb1 \
              libcurl4-openssl-dev \
              libfstrm0 \
              libh2o-evloop0.13 \
              liblmdb0 \
              libre2-5 \
              libssl-dev \
              libsystemd0 \
              libsodium23 \
              patch \
              protobuf-compiler \
              python3-venv snmpd prometheus')
    c.sudo('sed "s/agentxperms 0700 0755 dnsdist/agentxperms 0700 0755/g" regression-tests.dnsdist/snmpd.conf > /etc/snmp/snmpd.conf')
    c.sudo('systemctl start snmpd')

@task
def install_rec_build_deps(c):
    c.sudo('apt-get install -qq -y --no-install-recommends \
                autoconf \
                automake \
                ca-certificates \
                curl \
                bison \
                flex \
                g++ \
                git \
                libboost-all-dev \
                libcap-dev \
                libluajit-5.1-dev \
                libfstrm-dev \
                libsnmp-dev \
                libsodium-dev \
                libssl-dev \
                libsystemd-dev \
                libtool \
                make \
                pkg-config \
                ragel \
                systemd \
                python3-venv')

@task
def install_dnsdist_build_deps(c):
    c.sudo('apt-get install -qq -y --no-install-recommends \
                autoconf \
                automake \
                g++ \
                git \
                libboost-all-dev \
                libcap-dev \
                libcdb-dev \
                libedit-dev \
                libfstrm-dev \
                libh2o-evloop-dev \
                liblmdb-dev \
                libluajit-5.1-dev \
                libre2-dev \
                libsnmp-dev \
                libsodium-dev \
                libssl-dev \
                libsystemd-dev \
                libtool \
                make \
                pkg-config \
                ragel \
                systemd \
                python3-venv')

@task
def ci_autoconf(c):
    c.run('BUILDER_VERSION=0.0.0-git1 autoreconf -vfi')

@task
def ci_auth_configure(c):
    res = c.run('''CFLAGS="-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int" \
                   CXXFLAGS="-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int -Wp,-D_GLIBCXX_ASSERTIONS" \
                   ./configure \
                      CC='clang-11' \
                      CXX='clang++-11' \
                      --enable-option-checking=fatal \
                      --with-modules='bind geoip gmysql godbc gpgsql gsqlite3 ldap lmdb lua2 pipe random remote tinydns' \
                      --enable-systemd \
                      --enable-tools \
                      --enable-unit-tests \
                      --enable-backend-unit-tests \
                      --enable-fuzz-targets \
                      --enable-experimental-pkcs11 \
                      --enable-remotebackend-zeromq \
                      --with-lmdb=/usr \
                      --with-libsodium \
                      --prefix=/opt/pdns-auth \
                      --enable-ixfrdist \
                      --enable-asan \
                      --enable-ubsan''', warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)
@task
def ci_rec_configure(c):
    res = c.run('''            CFLAGS="-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int" \
            CXXFLAGS="-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int -Wp,-D_GLIBCXX_ASSERTIONS" \
            ./configure \
              CC='clang-11' \
              CXX='clang++-11' \
              --enable-option-checking=fatal \
              --enable-unit-tests \
              --enable-nod \
              --enable-systemd \
              --prefix=/opt/pdns-recursor \
              --with-libsodium \
              --with-lua=luajit \
              --with-libcap \
              --with-net-snmp \
              --enable-dns-over-tls \
              --enable-asan \
              --enable-ubsan''', warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)

@task
def ci_dnsdist_configure(c):
    res = c.run('''CFLAGS="-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int" \
                   CXXFLAGS="-O1 -Werror=vla -Werror=shadow -Wformat=2 -Werror=format-security -Werror=string-plus-int -Wp,-D_GLIBCXX_ASSERTIONS" \
                   ./configure \
                     CC='clang-11' \
                     CXX='clang++-11' \
                     --enable-option-checking=fatal \
                     --enable-unit-tests \
                     --enable-dnstap \
                     --enable-dnscrypt \
                     --enable-dns-over-tls \
                     --enable-dns-over-https \
                     --enable-systemd \
                     --prefix=/opt/dnsdist \
                     --with-libsodium \
                     --with-lua=luajit \
                     --with-libcap \
                     --with-re2 \
                     --enable-asan \
                     --enable-ubsan''', warn=True)
    if res.exited != 0:
        c.run('cat config.log')
        raise UnexpectedExit(res)

@task
def ci_auth_make(c):
    c.run('make -j8 -k V=1')

@task
def ci_rec_make(c):
    c.run('make -j8 -k V=1')

@task
def ci_dnsdist_make(c):
    c.run('make -j4 -k V=1')

@task
def ci_auth_install_remotebackend_ruby_deps(c):
    with c.cd('modules/remotebackend'):
      c.run('bundle config set path vendor/bundle')
      c.run('ruby -S bundle install')

@task
def ci_auth_run_unit_tests(c):
    res = c.run('make check', warn=True)
    if res.exited != 0:
      c.run('cat pdns/test-suite.log')
      raise UnexpectedExit(res)

@task
def ci_rec_run_unit_tests(c):
    res = c.run('make check', warn=True)
    if res.exited != 0:
      c.run('cat test-suite.log')
      raise UnexpectedExit(res)

@task
def ci_dnsdist_run_unit_tests(c):
    res = c.run('make check', warn=True)
    if res.exited != 0:
      c.run('cat test-suite.log')
      raise UnexpectedExit(res)

@task
def ci_make_install(c):
    res = c.run('make install')

@task
def add_auth_repo(c):
    dist = 'ubuntu' # FIXME take these from the caller?
    release = 'focal'
    version = '44'

    c.sudo('apt-get install -qq -y curl gnupg2')
    if version == 'master':
        c.sudo('curl https://repo.powerdns.com/CBC8B383-pub.asc | apt-key add -')
    else:
        c.sudo('curl https://repo.powerdns.com/FD380FBB-pub.asc | apt-key add -')
    c.sudo(f"echo 'deb [arch=amd64] http://repo.powerdns.com/{dist} {release}-auth-{version} main' >> /etc/apt/sources.list.d/pdns.list")
    c.sudo("echo 'Package: pdns-*' > /etc/apt/preferences.d/pdns") # FIXME three subprocess calls?
    c.sudo("echo 'Pin: origin repo.powerdns.com' >> /etc/apt/preferences.d/pdns")
    c.sudo("echo 'Pin-Priority: 600' >> /etc/apt/preferences.d/pdns")
    c.sudo('apt-get update')

@task
def test_api(c, product, backend=''):
    with c.cd('regression-tests.api'):
        c.run(f'PDNSRECURSOR=/opt/pdns-recursor/sbin/pdns_recursor ./runtests {product} {backend}')

@task
def test_dnsdist(c):
    with c.cd('regression-tests.dnsdist'):
        c.run('DNSDISTBIN=/opt/dnsdist/bin/dnsdist ./runtests')