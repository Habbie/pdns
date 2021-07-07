from invoke import task
from invoke.exceptions import UnexpectedExit

import sys

@task
def apt_fresh(c):
    c.sudo('apt-get update')
    c.sudo('apt-get dist-upgrade')

@task
def install_clang(c):
    c.sudo('apt-get -qq -y --no-install-recommends install clang-11 llvm-11')

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

@task
def install_rec_build_deps(c):
    c.sudo('apt-get update && sudo apt-get install -qq -y --no-install-recommends \
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
def ci_auth_make(c):
    c.run('make -j8 -k V=1')

@task
def ci_rec_make(c):
    c.run('make -j8 -k V=1')

@task
def ci_auth_install_remotebackend_ruby_deps(c):
    with c.cd('modules/remotebackend'):
      c.run('ruby -S bundle install --path vendor/bundle')

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
def ci_make_install(c):
    res = c.run('make install')
