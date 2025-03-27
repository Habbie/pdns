Views
=====

Views are an experimental feature, which allows the scope of zones to be
narrowed, depending on the originating address of the query, by exposing
different `variants` of zones.

A simple use case for this feature is to separate internal (trusted) and
external (untrusted) views of a given domain, without having to rely upon a
GeoIP-like backend.

Requirements
------------

The `Views` features is currently only available in the :doc:`LMDB
<backends/lmdb>` backend, and requires the zone cache to be enabled (by setting
:ref:`setting-zone-cache-refresh-interval` to a non-zero value).

It must be explicitly enabled using :ref:`setting-views` in the configuration
file.

Concepts
--------

The first piece of the Views puzzle is the `network`. A `network`, specified as
a base address and a prefix length, is associated to a `view name`. The `view
name` in turn, will select a set of `zone variants` to be used to answer queries
for these zones, originating from this network.

Queries originating from no configured network will be answered as in a
non-views setup, without any restriction.

Zone Variants
^^^^^^^^^^^^^

A Zone Variant is a zone on its own, written as ``<zone name>:<variant name>``.
Variant names are made of lowercase letters, digits, underscore and dashes only.

For example, the following variants are valid:

- ``example.org:variant01``
- ``example.org:1st_variant``
- ``example.org:othervariant``

Zone variants can be used in any command or operation where a zone name is
expected, i.e. with :doc:`pdnsutil <manpages/pdnsutil.1>` or the
:doc:`HTTP API <http-api/index>`.

There is no mechanism to populate a freshly-created variant from the variantless
zone contents.

Networks
^^^^^^^^

Networks are set up either with :doc:`pdnsutil <manpages/pdnsutil.1>` or the
:doc:`HTTP API <http-api/index>`.

Every network is associated to a unique view name.

Views
^^^^^

Views are set up either with :doc:`pdnsutil <manpages/pdnsutil.1>` or the
:doc:`HTTP API <http-api/index>`.

Every view is associated to a list of zone variants. It can also include
regular (variantless) zones, but this is not needed as all zones which do not
appear in a view will operate as in a non-views setup.

In other words, zones not part of a view are always implicitly available in
that view, as their variantless contents.

Only one variant per zone may appear in a view; setting a new zone variant will
replace the previous one in the view.
