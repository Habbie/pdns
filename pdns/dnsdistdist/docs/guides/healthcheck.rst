Health checks
=============

dnsdist uses a health check, sent once every second, to determine the availability of a backend server.

By default, an A query for "a.root-servers.net." is sent.
A different query type and target can be specified by passing, respectively, the ``checkType`` and ``checkName`` parameters to :func:`newServer`.

The default behavior is to consider any valid response with an RCODE different from ServFail as valid.
If the ``mustResolve`` parameter of :func:`newServer` is set to ``true``, a response will only be considered valid if its RCODE differs from NXDomain, ServFail and Refused.

The number of health check failures before a server is considered down is configurable via the ``maxCheckFailures`` parameter, defaulting to 1.
The CD flag can be set on the query by setting ``setCD`` to true.
e.g.::

  newServer({address="192.0.2.1", checkType="AAAA", checkName="a.root-servers.net.", mustResolve=true})
