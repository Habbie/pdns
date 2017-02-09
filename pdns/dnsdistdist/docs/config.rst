.. highlight:: lua

Configuration Reference
=======================

This page lists all configuration options for dnsdist.

Parameters have a capitilized type appended, these are:

* ``IP``: An IP address
* ``PORT``: A port number, a number between 1 and 65535
* ``NUM``: A number
* ``STRING``: A string
* ``BOOL``: A boolean, either ``true`` or ``false``

.. note::

  When an IPv6 IP:PORT combination is needed, the bracketed syntax from :rfc:`RFC 3986 <3986#section-3.2.2>` should be used.
  e.g. "[2001:DB8:14::C0FF:FEE]:5300".

Global configuration
--------------------

Access Control Lists
~~~~~~~~~~~~~~~~~~~~

EDNS Client Subnet
~~~~~~~~~~~~~~~~~~

.. function:: setECSSourcePrefixV4(NUM)

  When ``useClientSubnet`` in :func:`newServer` is set and dnsdist add an EDNS Client Subnet Client option to the query, truncate the requestors IPv4 address to NUM bits

.. function:: setECSSourcePrefixV6(NUM)

  When ``useClientSubnet`` in :func:`newServer` is set and dnsdist add an EDNS Client Subnet Client option to the query, truncate the requestor's IPv6 address to NUM bits

Servers
-------

.. function:: newServer(server_string)
              newServer(server_table)

  Add a new backend server. Call this function with either a string::

    newServer(
      "IP:PORT" -- IP and PORT of the backend server
    )

  or a table::

    newServer({
      address="IP:PORT",     -- IP and PORT of the backend server (mandatory)
      qps=NUM,               -- Limit the number of queries per second to NUM
      order=NUM,             -- The order of this server
      weight=NUM,            -- The weight of this server
      pool=STRING,           -- The pool this server belongs to (unset or empty string means default pool)
      retries=NUM,           --
      tcpConnectTimeout=NUM, --
      tcpSendTimeout=NUM,    --
      tcpRecvTimeout=NUM,    --
      checkName=STRING,      -- Use STRING as QNAME in the health-check query, default: "a.root-servers.net."
      checkType=STRING,      -- Use STRING as QTYPE in the health-check query, default: "A"
      setCD=BOOL,            -- Set the CD (Checking Disabled) flag in the health-check query, default: false
      maxCheckFailures=NUM,  -- Allow NUM check failures before declaring the backend down, default: false
      mustResolve=BOOL,      -- Set to true when the health check MUST return a NOERROR RCODE and an answer
      useClientSubnet=BOOL,  -- Add the client's IP address in the EDNS Client Subnet option when forwarding the query to this backend
      source=STRING          -- The source address or interface to use for queries to this backend, by default this is left to the kernel's address selection
                             -- The following formats are supported:
                             --   "address", e.g. "192.0.2.2"
                             --   "interface name", e.g. "eth0"
                             --   "address@interface", e.g. "192.0.2.2@eth0"
    })

  :param str server_string: A simple IP:PORT string.
  :param table server_table: A table with at least a 'name' key

.. function:: getServer(index) -> Server

  Get a :class:`Server`

  :param int index: The number of the server (as seen in :func:`showServers`).
  :returns:  The :class:`Server` object or nil

.. function:: getServers()

  Returns a table with all defined servers.

.. function:: rmServer(index)
              rmServer(server)

  Remove a backend server.

  :param int index: The number of the server (as seen in :func:`showServers`).
  :param Server server: A :class:`Server` object as returned by e.g. :func:`getServer`.

Server Functions
~~~~~~~~~~~~~~~~
A server object returned by :func:`getServer` can be manipulated with these functions.

.. class:: Server

  This object represents a backend server. It has several methods.

.. classmethod:: Server:addPool(pool)

  Add this server to a pool.

  :param str pool: The pool to add the server to

.. classmethod:: Server:getName() -> string

  Get the name of this server.

  :returns: The name of the server, or an empty string if it does not have one

.. classmethod:: Server:getNameWithAddr() -> string

  Get the name plus IP address and port of the server

  :returns: A string containing the server name if any plus the server address and port

.. classmethod:: Server:getOutstanding() -> int

  Get the number of outstanding queries for this server.

  :returns: The number of outstanding queries

.. classmethod:: Server:isUp() -> bool

  Returns the up status of the server

  :returns: true when the server is up, false otherwise

.. classmethod:: Server:rmPool(pool)

  Removes the server from the named pool

  :param str pool: The pool to remove the server from

.. classmethod:: Server:setAuto()

  Set the server in the default auto state.
  This will enable health check queries that will set the server ``up`` and ``down`` appropriatly.

.. classmethod:: Server:setQPS(limit)

  Limit the queries per second for this server.

  :param int limit: The maximum number of queries per second

.. classmethod:: Server:setDown()

  Set the server in an ``DOWN`` state.
  The server will not receive queries and the health checks are disabled

.. classmethod:: Server:setUp()

  Set the server in an ``UP`` state.
  This server will still receive queries and health checks are disabled

Attributes
~~~~~~~~~~

.. attribute:: Server.name

  The name of the server

.. attribute:: Server.upStatus

  Whether or not this server is up or down

.. attribute:: Server.order

  The order of the server

.. attribute:: Server.weight

  The weight of the server


Status
------

.. function:: showServers()

  This function shows all backend servers currently configured and some statistics.
  These statics have the following fields:

  * ``#`` - The number of the server, can be used as the argument for :func:`getServer`
  * ``Address`` - The IP address and port of the server
  * ``State`` - The current state of the server
  * ``Qps`` - Current number of queries per second
  * ``Qlim`` - Configured maximum number of queries per second
  * ``Ord`` - The order number of the server
  * ``Wt`` - The weight of the server
  * ``Queries`` - Total amount of queries sent to this server
  * ``Drops`` - Number of queries that were dropped by this server
  * ``Drate`` - Number of queries dropped per second by this server
  * ``Lat`` - The latency of this server in milliseconds
  * ``Pools`` - The pools this server belongs to
