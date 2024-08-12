/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE unit

#include "config.h"

#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/tuple/tuple.hpp>

#include "lmdb-safe.hh"

BOOST_AUTO_TEST_SUITE(test_lmdb_safe)

BOOST_AUTO_TEST_CASE(test_ntoh128)
{
  {
    uint32_t fixtureNet = 1; // Network byte order
    uint32_t fixtureHost = networkToHostByteOrder(fixtureNet); // Host byte order
    BOOST_CHECK_EQUAL(fixtureHost, 16777216);
    BOOST_CHECK_EQUAL(fixtureHost & 0x01000000, fixtureHost);
  }

  {
    uint32_t fixtureNet = 16777216; // Network byte order
    uint32_t fixtureHost = networkToHostByteOrder(fixtureNet); // Host byte order
    BOOST_CHECK_EQUAL(fixtureHost, 1);
    BOOST_CHECK_EQUAL(fixtureHost & 0x00000001, fixtureHost);
  }

  {
    uint128_t testDataNet{{0, 0, 0, 1}}; // Network byte order
    uint128_t testDataHost = networkToHostByteOrder(testDataNet); // Host byte order
    uint128_t testDataExpected{{16777216, 0, 0, 0}};
    BOOST_CHECK_EQUAL(testDataHost, testDataExpected);
  }

  {
    uint128_t testDataNet{{16777216, 0, 0, 0}}; // Network byte order
    uint128_t testDataHost = networkToHostByteOrder(testDataNet); // Host byte order
    uint128_t testDataExpected{{0, 0, 0, 1}};
    BOOST_CHECK_EQUAL(testDataHost, testDataExpected);
  }
}

BOOST_AUTO_TEST_CASE(test_hton128)
{
  {
    uint32_t fixtureHost = 1; // Network byte order
    uint32_t fixtureNet = hostToNetworkByteOrder(fixtureHost); // Host byte order
    BOOST_CHECK_EQUAL(fixtureNet, 16777216);
    BOOST_CHECK_EQUAL(fixtureNet & 0x01000000, fixtureNet);
  }

  {
    uint32_t fixtureHost = 16777216; // Network byte order
    uint32_t fixtureNet = hostToNetworkByteOrder(fixtureHost); // Host byte order
    BOOST_CHECK_EQUAL(fixtureNet, 1);
    BOOST_CHECK_EQUAL(fixtureNet & 0x00000001, fixtureNet);
  }

  {
    uint128_t testDataHost{{0, 0, 0, 1}}; // Network byte order
    uint128_t testDataNet = hostToNetworkByteOrder(testDataHost); // Host byte order
    uint128_t testDataExpected{{16777216, 0, 0, 0}};
    BOOST_CHECK_EQUAL(testDataNet, testDataExpected);
  }

  {
    uint128_t testDataHost{{16777216, 0, 0, 0}}; // Network byte order
    uint128_t testDataNet = hostToNetworkByteOrder(testDataHost); // Host byte order
    uint128_t testDataExpected{{0, 0, 0, 1}};
    BOOST_CHECK_EQUAL(testDataNet, testDataExpected);
  }
}

BOOST_AUTO_TEST_SUITE_END();
