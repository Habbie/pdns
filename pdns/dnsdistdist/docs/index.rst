dnsdist Overview
================

dnsdist is a highly DNS-, DoS- and abuse-aware loadbalancer.
Its goal in life is to route traffic to the best server, delivering top performance to legitimate users while shunting or blocking abusive traffic.

dnsdist is dynamic, its configuration language is `Lua <http://lualang.org>`_ and it can be can be changed at runtime, and its statistics can be queried from a console-like interface or an HTTP API.

A configuration to balance DNS queries to several backend servers:

.. code-block:: lua

   newServer({address="2001:4860:4860::8888", qps=1})
   newServer({address="2001:4860:4860::8844", qps=1})
   newServer({address="2620:0:ccc::2", qps=10})
   newServer({address="2620:0:ccd::2", name="dns1", qps=10})
   newServer("192.168.1.2")
   setServerPolicy(firstAvailable) -- first server within its QPS limit

Running dnsdist
---------------

If you have not worked with dnsdist before, here are some resources to get you going:

* :doc:`Install dnsdist <install>`.
* To dive in immediately, see the :doc:`Quickstart Guide <quickstart>`.
* The :doc:`Introduction <introduction>` page covers the rationale of dnsdist.
* There are several :doc:`guides/index` about the different functions
* :doc:`advanced` describes some of the more advanced features and internals
* All functions and classes are described in the :doc:`config`

Questions, requests or comments?
--------------------------------

There are several ways to reach us:

* The `dnsdist mailing-list <https://mailman.powerdns.com/mailman/listinfo/dnsdist>`_
* #powerdns on `irc.oftc.net <irc://irc.oftc.net/#powerdns>`_

If you require commercial support, please see the `PowerDNS.com website <https://powerdns.com>`_ or email us at powerdns.support.sales@powerdns.com.

