Packet Policies
===============

dnsdist works in essence like any other loadbalancer:

It receives packets on one or several addresses it listens on, it then determines whether it will process this packet based on the :doc:`advanced/acl`, should be packet be processed, dnsdist attempts to match any of the configured rules in order and when one matches, the associated action is performed.

These rule and action combinations are considered policies.

Packet Actions
--------------

Each packet can be:

- Dropped
- Turned into an answer directly
- Forwarded to a downstream server
- Modified and forwarded to a downstream and be modified back
- Be delayed

.. _RulesIntro:

Matching Packets (Rules)
------------------------
