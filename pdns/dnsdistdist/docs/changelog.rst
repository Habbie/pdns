Changelog
=========

1.1.0
-----

Released December 29th 2016

Changes since 1.1.0-beta2:

Improvements
~~~~~~~~~~~~

-  `#4783 <https://github.com/PowerDNS/pdns/pull/4783>`__: Add -latomic
   on powerpc
-  `#4812 <https://github.com/PowerDNS/pdns/pull/4812>`__: Handle
   header-only responses, handle Refused as Servfail in the cache

Bug fixes
~~~~~~~~~

-  `#4762 <https://github.com/PowerDNS/pdns/pull/4762>`__:
   SuffixMatchNode: Fix an insertion issue for an existing node
-  `#4772 <https://github.com/PowerDNS/pdns/pull/4772>`__: Fix dnsdist
   initscript config check

1.1.0-beta2
-----------

Released December 14th 2016

Changes since 1.1.0-beta1:

New features
~~~~~~~~~~~~

-  `#4518 <https://github.com/PowerDNS/pdns/pull/4518>`__: Fix dynblocks
   over TCP, allow refusing dyn blocked queries
-  `#4519 <https://github.com/PowerDNS/pdns/pull/4519>`__: Allow
   altering the ECS behavior via rules and Lua
-  `#4535 <https://github.com/PowerDNS/pdns/pull/4535>`__: Add
   ``DNSQuestion:getDO()``
-  `#4653 <https://github.com/PowerDNS/pdns/pull/4653>`__:
   ``getStatisticsCounters()`` to access counters from Lua
-  `#4657 <https://github.com/PowerDNS/pdns/pull/4657>`__: Add
   ``includeDirectory(dir)``
-  `#4658 <https://github.com/PowerDNS/pdns/pull/4658>`__: Allow editing
   the ACL via the API
-  `#4702 <https://github.com/PowerDNS/pdns/pull/4702>`__: Add
   ``setUDPTimeout(n)``
-  `#4726 <https://github.com/PowerDNS/pdns/pull/4726>`__: Add an option
   to return ServFail when no server is available
-  `#4748 <https://github.com/PowerDNS/pdns/pull/4748>`__: Add
   ``setCacheCleaningPercentage()``

Improvements
~~~~~~~~~~~~

-  `#4533 <https://github.com/PowerDNS/pdns/pull/4533>`__: Fix building
   with clang on OS X and FreeBSD
-  `#4537 <https://github.com/PowerDNS/pdns/pull/4537>`__: Replace
   luawrapper's std::forward/std::make\_tuple combo with
   std::forward\_as\_tuple (Sangwhan "fish" Moon)
-  `#4596 <https://github.com/PowerDNS/pdns/pull/4596>`__: Change the
   default max number of queued TCP conns to 1000
-  `#4632 <https://github.com/PowerDNS/pdns/pull/4632>`__: Improve
   dnsdist error message on a common typo/config mistake
-  `#4694 <https://github.com/PowerDNS/pdns/pull/4694>`__: Don't use a
   const\_iterator for erasing (fix compilation with some versions of
   gcc)
-  `#4715 <https://github.com/PowerDNS/pdns/pull/4715>`__: Specify that
   dnsmessage.proto uses protobuf version 2
-  `#4765 <https://github.com/PowerDNS/pdns/pull/4765>`__: Some service
   improvements

Bug fixes
~~~~~~~~~

-  `#4425 <https://github.com/PowerDNS/pdns/pull/4425>`__: Fix a
   protobuf regression (requestor/responder mix-up) caused by a94673e
-  `#4541 <https://github.com/PowerDNS/pdns/pull/4541>`__: Fix insertion
   issues in SuffixMatchTree, move it to dnsname.hh
-  `#4553 <https://github.com/PowerDNS/pdns/pull/4553>`__: Flush output
   in single command client mode
-  `#4578 <https://github.com/PowerDNS/pdns/pull/4578>`__: Fix
   destination address reporting
-  `#4640 <https://github.com/PowerDNS/pdns/pull/4640>`__: Don't exit
   dnsdist on an exception in maintenance
-  `#4721 <https://github.com/PowerDNS/pdns/pull/4721>`__: Handle
   exceptions in the UDP responder thread
-  `#4734 <https://github.com/PowerDNS/pdns/pull/4734>`__: Add the TCP
   socket to the map only if the connection succeeds. Closes #4733
-  `#4742 <https://github.com/PowerDNS/pdns/pull/4742>`__: Decrement the
   queued TCP conn count if writing to the pipe fails
-  `#4743 <https://github.com/PowerDNS/pdns/pull/4743>`__: Ignore
   newBPFFilter() and newDynBPFFilter() in client mode
-  `#4753 <https://github.com/PowerDNS/pdns/pull/4753>`__: Fix FD leak
   on TCP connection failure, handle TCP worker creation failure
-  `#4764 <https://github.com/PowerDNS/pdns/pull/4764>`__: Prevent race
   while creating new TCP worker threads

1.1.0-beta1
-----------

Released September 1st 2016

Changes since 1.0.0:

New features
~~~~~~~~~~~~

-  `#3762 <https://github.com/PowerDNS/pdns/pull/3762>`__ Teeaction:
   send copy of query to second nameserver, sponge responses
-  `#3876 <https://github.com/PowerDNS/pdns/pull/3876>`__ Add
   ``showResponseRules()``, ``{mv,rm,top}ResponseRule()``
-  `#3936 <https://github.com/PowerDNS/pdns/pull/3936>`__ Filter on
   opcode, records count/type, trailing data
-  `#3975 <https://github.com/PowerDNS/pdns/pull/3975>`__ Make dnsdist
   {A,I}XFR aware, document possible issues
-  `#4006 <https://github.com/PowerDNS/pdns/pull/4006>`__ Add eBPF
   source address and qname/qtype filtering
-  `#4008 <https://github.com/PowerDNS/pdns/pull/4008>`__ Node
   infrastructure for querying recent traffic
-  `#4042 <https://github.com/PowerDNS/pdns/pull/4042>`__ Add
   server-side TCP Fast Open support
-  `#4050 <https://github.com/PowerDNS/pdns/pull/4050>`__ Add
   ``clearRules()`` and ``setRules()``
-  `#4114 <https://github.com/PowerDNS/pdns/pull/4114>`__ Add
   ``QNameLabelsCountRule()`` and ``QNameWireLengthRule()``
-  `#4116 <https://github.com/PowerDNS/pdns/pull/4116>`__ Added src
   boolean to NetmaskGroupRule to match destination address (Reinier
   Schoof)
-  `#4175 <https://github.com/PowerDNS/pdns/pull/4175>`__ Implemented
   query counting (Reinier Schoof)
-  `#4244 <https://github.com/PowerDNS/pdns/pull/4244>`__ Add a
   ``setCD`` parameter to set cd=1 on health check queries
-  `#4284 <https://github.com/PowerDNS/pdns/pull/4284>`__ Add
   RCodeRule(), Allow, Delay and Drop response actions
-  `#4305 <https://github.com/PowerDNS/pdns/pull/4305>`__ Add an
   optional Lua callback for altering a Protobuf message
-  `#4309 <https://github.com/PowerDNS/pdns/pull/4309>`__ Add
   showTCPStats function (RobinGeuze)
-  `#4329 <https://github.com/PowerDNS/pdns/pull/4329>`__ Add options to
   LogAction() so it can append (instead of truncate) (Duane Wessels)

Improvements
~~~~~~~~~~~~

-  `#3714 <https://github.com/PowerDNS/pdns/pull/3714>`__ Add
   documentation links to dnsdist.service (Ruben Kerkhof)
-  `#3754 <https://github.com/PowerDNS/pdns/pull/3754>`__ Allow the use
   of custom headers in the web server
-  `#3826 <https://github.com/PowerDNS/pdns/pull/3826>`__ Implement a
   'quiet' mode for SuffixMatchNodeRule()
-  `#3836 <https://github.com/PowerDNS/pdns/pull/3836>`__ Log the
   content of webserver's exceptions
-  `#3858 <https://github.com/PowerDNS/pdns/pull/3858>`__ Only log
   YaHTTP's parser exceptions in verbose mode
-  `#3877 <https://github.com/PowerDNS/pdns/pull/3877>`__ Increase max
   FDs in systemd unit, warn if clearly too low
-  `#4019 <https://github.com/PowerDNS/pdns/pull/4019>`__ Add an
   optional ``addECS`` option to ``TeeAction()``
-  `#4029 <https://github.com/PowerDNS/pdns/pull/4029>`__ Add version
   and feature information to version output
-  `#4079 <https://github.com/PowerDNS/pdns/pull/4079>`__ Return an
   error on RemoteLog{,Response}Action() w/o protobuf
-  `#4246 <https://github.com/PowerDNS/pdns/pull/4246>`__ API now sends
   pools as a JSON array instead of a string
-  `#4302 <https://github.com/PowerDNS/pdns/pull/4302>`__ Add ``help()``
   and ``showVersion()``
-  `#4286 <https://github.com/PowerDNS/pdns/pull/4286>`__ Add response
   rules to the API and Web status page
-  `#4068 <https://github.com/PowerDNS/pdns/pull/4068>`__ Display the
   dyn eBPF filters stats in the web interface

Bug fixes
~~~~~~~~~

-  `#3755 <https://github.com/PowerDNS/pdns/pull/3755>`__ Fix RegexRule
   example in dnsdistconf.lua
-  `#3773 <https://github.com/PowerDNS/pdns/pull/3773>`__ Stop copying
   the HTTP request headers to the response
-  `#3837 <https://github.com/PowerDNS/pdns/pull/3837>`__ Remove dnsdist
   service file on trusty
-  `#3840 <https://github.com/PowerDNS/pdns/pull/3840>`__ Catch
   WrongTypeException in client mode
-  `#3906 <https://github.com/PowerDNS/pdns/pull/3906>`__ Keep the
   servers ordered inside pools
-  `#3988 <https://github.com/PowerDNS/pdns/pull/3988>`__ Fix
   ``grepq()`` output in the README
-  `#3992 <https://github.com/PowerDNS/pdns/pull/3992>`__ Fix some typos
   in the AXFR/IXFR documentation
-  `#3995 <https://github.com/PowerDNS/pdns/pull/3995>`__ Fix comparison
   between signed and unsigned integer
-  `#4049 <https://github.com/PowerDNS/pdns/pull/4049>`__ Fix dnsdist
   rpm building script #4048 (Daniel Stirnimann)
-  `#4065 <https://github.com/PowerDNS/pdns/pull/4065>`__ Include
   editline/readline.h instead of readline.h/history.h
-  `#4067 <https://github.com/PowerDNS/pdns/pull/4067>`__ Disable eBPF
   support when BPF\_FUNC\_tail\_call is not found
-  `#4069 <https://github.com/PowerDNS/pdns/pull/4069>`__ Fix a buffer
   overflow when displaying an OpcodeRule
-  `#4101 <https://github.com/PowerDNS/pdns/pull/4101>`__ Fix $
   expansion in build-dnsdist-rpm
-  `#4198 <https://github.com/PowerDNS/pdns/pull/4198>`__ newServer
   setting maxCheckFailures makes no sense (stutiredboy)
-  `#4205 <https://github.com/PowerDNS/pdns/pull/4205>`__ Prevent the
   use of "any" addresses for downstream server
-  `#4220 <https://github.com/PowerDNS/pdns/pull/4220>`__ Don't log an
   error when parsing an invalid UDP query
-  `#4348 <https://github.com/PowerDNS/pdns/pull/4348>`__ Fix invalid
   outstanding count for {A,I}XFR over TCP
-  `#4365 <https://github.com/PowerDNS/pdns/pull/4365>`__ Reset origFD
   asap to keep the outstanding count correct
-  `#4375 <https://github.com/PowerDNS/pdns/pull/4375>`__ Tuple requires
   make\_tuple to initialize
-  `#4380 <https://github.com/PowerDNS/pdns/pull/4380>`__ Fix
   compilation with clang when eBPF support is enabled

1.0.0
-----

Released April 21st 2016

Changes since 1.0.0-beta1:

Improvements
~~~~~~~~~~~~

-  `#3700 <https://github.com/PowerDNS/pdns/pull/3700>`__ Create user
   from the RPM package to drop privs
-  `#3712 <https://github.com/PowerDNS/pdns/pull/3712>`__ Make check
   should run testrunner
-  `#3713 <https://github.com/PowerDNS/pdns/pull/3713>`__ Remove
   contrib/dnsdist.service (Ruben Kerkhof)
-  `#3722 <https://github.com/PowerDNS/pdns/pull/3722>`__ Use LT\_INIT
   and disable static objects (Ruben Kerkhof)
-  `#3724 <https://github.com/PowerDNS/pdns/pull/3724>`__ Include
   PDNS\_CHECK\_OS in configure (Christian Hofstaedtler)
-  `#3728 <https://github.com/PowerDNS/pdns/pull/3728>`__ Document
   libedit Ctrl-R workaround for CentOS 6
-  `#3730 <https://github.com/PowerDNS/pdns/pull/3730>`__ Make
   ``topBandwidth()`` behave like other top\* functions
-  `#3731 <https://github.com/PowerDNS/pdns/pull/3731>`__ Clarify a bit
   the documentation of load-balancing policies

Bug fixes
~~~~~~~~~

-  `#3711 <https://github.com/PowerDNS/pdns/pull/3711>`__ Building rpm
   needs systemd headers (Ruben Kerkhof)
-  `#3736 <https://github.com/PowerDNS/pdns/pull/3736>`__ Add missing
   Lua binding for NetmaskGroupRule()
-  `#3739 <https://github.com/PowerDNS/pdns/pull/3739>`__ Drop
   privileges after daemonizing and writing our pid

1.0.0-beta1
-----------

Released April 14th 2016

Changes since 1.0.0-alpha2:

New features
~~~~~~~~~~~~

-  Per-pool packet cache
-  Some actions do not stop the processing anymore when they match,
   allowing more complex setups: Delay, Disable Validation, Log,
   MacAddr, No Recurse and of course None
-  The new RE2Rule() is available, using the RE2 regular expression
   library to match queries, in addition to the existing POSIX-based
   RegexRule()
-  SpoofAction() now supports multiple A and AAAA records
-  Remote logging of questions and answers via Protocol Buffer

Improvements
~~~~~~~~~~~~

-  `#3405 <https://github.com/PowerDNS/pdns/pull/3405>`__ Add health
   check logging, ``maxCheckFailures`` to backend
-  `#3412 <https://github.com/PowerDNS/pdns/pull/3412>`__ Check config
-  `#3440 <https://github.com/PowerDNS/pdns/pull/3440>`__ Client
   operation improvements
-  `#3466 <https://github.com/PowerDNS/pdns/pull/3466>`__ Add dq binding
   for skipping packet cache in LuaAction (Jan Broer)
-  `#3499 <https://github.com/PowerDNS/pdns/pull/3499>`__ Add support
   for multiple carbon servers
-  `#3504 <https://github.com/PowerDNS/pdns/pull/3504>`__ Allow
   accessing the API with an optional API key
-  `#3556 <https://github.com/PowerDNS/pdns/pull/3556>`__ Add an option
   to limit the number of queued TCP connections
-  `#3578 <https://github.com/PowerDNS/pdns/pull/3578>`__ Add a
   ``disable-syslog`` option
-  `#3608 <https://github.com/PowerDNS/pdns/pull/3608>`__ Export cache
   stats to carbon
-  `#3622 <https://github.com/PowerDNS/pdns/pull/3622>`__ Display the
   ACL content on startup
-  `#3627 <https://github.com/PowerDNS/pdns/pull/3627>`__ Remove ECS
   option from response's OPT RR when necessary
-  `#3633 <https://github.com/PowerDNS/pdns/pull/3633>`__ Count "TTL too
   short" cache events
-  `#3677 <https://github.com/PowerDNS/pdns/pull/3677>`__ systemd-notify
   support

Bug fixes
~~~~~~~~~

-  `#3388 <https://github.com/PowerDNS/pdns/pull/3388>`__ Lock the Lua
   context before executing a LuaAction
-  `#3433 <https://github.com/PowerDNS/pdns/pull/3433>`__ Check that the
   answer matches the initial query
-  `#3461 <https://github.com/PowerDNS/pdns/pull/3461>`__ Fix crash when
   calling rmServer() with an invalid index
-  `#3550 <https://github.com/PowerDNS/pdns/pull/3550>`__,\ `#3551 <https://github.com/PowerDNS/pdns/pull/3551>`__
   Fix build failure on FreeBSD (Ruben Kerkhof)
-  `#3594 <https://github.com/PowerDNS/pdns/pull/3594>`__ Prevent EOF
   error for empty console response w/o sodium
-  `#3634 <https://github.com/PowerDNS/pdns/pull/3634>`__ Prevent
   dangling TCP fd in case setupTCPDownstream() fails
-  `#3641 <https://github.com/PowerDNS/pdns/pull/3641>`__ Under
   threshold, QPS action should return None, not Allow
-  `#3658 <https://github.com/PowerDNS/pdns/pull/3658>`__ Fix a race
   condition in MaxQPSIPRule

1.0.0-alpha2
------------

Released February 5th 2016

Changes since 1.0.0-alpha1:

New features
~~~~~~~~~~~~

-  Lua functions now receive a DNSQuestion ``dq`` object instead of
   several parameters. This adds a greater compatibility with PowerDNS
   and allows adding more parameters without breaking the API
   (`#3198 <https://github.com/PowerDNS/pdns/issues/3198>`__)
-  Added a ``source`` option to ``newServer()`` to specify the local
   address or interface used to contact a downstream server
   (`#3138 <https://github.com/PowerDNS/pdns/issues/3138>`__)
-  CNAME and IPv6-only support have been added to spoofed responses
   (`#3064 <https://github.com/PowerDNS/pdns/issues/3064>`__)
-  ``grepq()`` can be used to search for slow queries, along with
   ``topSlow()``
-  New Lua functions: ``addDomainCNAMESpoof()``, ``AllowAction()`` by
   @bearggg, ``exceedQRate()``, ``MacAddrAction()``, ``makeRule()``,
   ``NotRule()``, ``OrRule()``, ``QClassRule()``, ``RCodeAction()``,
   ``SpoofCNAMEAction()``, ``SuffixMatchNodeRule()``, ``TCPRule()``,
   ``topSlow()``
-  ``NetmaskGroup`` support have been added in Lua
   (`#3144 <https://github.com/PowerDNS/pdns/issues/3144>`__)
-  Added ``MacAddrAction()`` to add the source MAC address to the
   forwarded query
   (`#3313 <https://github.com/PowerDNS/pdns/issues/3313>`__)

Bug fixes
~~~~~~~~~

-  An issue in DelayPipe could make dnsdist crash at startup
-  ``downstream-timeouts`` metric was not always updated
-  ``truncateTC`` was unproperly updating the response length
   (`#3126 <https://github.com/PowerDNS/pdns/issues/3126>`__)
-  DNSCrypt responses larger than queries were unproperly truncated
-  An issue prevented info message from being displayed in non-verbose
   mode, fixed by Jan Broer
-  Reinstating an expired Dynamic Rule was not correctly logged
   (`#3323 <https://github.com/PowerDNS/pdns/issues/3323>`__)
-  Initialized counters in the TCP client thread might have cause FD and
   memory leak, reported by Martin Pels
   (`#3300 <https://github.com/PowerDNS/pdns/issues/3300>`__)
-  We now drop queries containing no question (qdcount == 0)
   (`#3290 <https://github.com/PowerDNS/pdns/issues/3290>`__)
-  Outstanding TCP queries count was not always correct
   (`#3288 <https://github.com/PowerDNS/pdns/issues/3288>`__)
-  A locking issue in exceedRespGen() might have caused crashs
   (`#3277 <https://github.com/PowerDNS/pdns/issues/3277>`__)
-  Useless sockets were created in client mode
   (`#3257 <https://github.com/PowerDNS/pdns/issues/3257>`__)
-  ``addAnyTCRule()`` was generating TC=1 responses even over TCP
   (`#3251 <https://github.com/PowerDNS/pdns/issues/3251>`__)

Web interface
~~~~~~~~~~~~~

-  Cleanup of the HTML by Sander Hoentjen
-  Fixed an XSS reported by @janeczku
   (`#3217 <https://github.com/PowerDNS/pdns/issues/3217>`__)
-  Removed remote images
-  Set the charset to UTF-8, added some security-related and CORS HTTP
   headers
-  Added server latency by Jan Broer
   (`#3201 <https://github.com/PowerDNS/pdns/issues/3201>`__)
-  Switched to official minified versions of JS scripts, by Sander
   Hoentjen (`#3317 <https://github.com/PowerDNS/pdns/issues/3317>`__)
-  Don't log unauthenticated HTTP request as an authentication failure

Various documentation updates and minor cleanups:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Added documentation for Advanced DNS Protection features (Dynamic
   rules, ``maintenance()``)
-  Make ``topBandwidth()`` default to the top 10 clients
-  Replaced readline with libedit
-  Added GPL2 License
   (`#3200 <https://github.com/PowerDNS/pdns/issues/3200>`__)
-  Added incbin License
   (`#3269 <https://github.com/PowerDNS/pdns/issues/3269>`__)
-  Updated completion rules
-  Removed wrong option ``--daemon-no`` by Stefan Schmidt

1.0.0-alpha1
------------

Released December 24th 2015

Initial release
