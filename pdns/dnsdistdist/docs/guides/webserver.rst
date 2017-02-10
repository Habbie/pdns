Built-in webserver
==================

To visually interact with dnsdist, try adding:

.. code-block:: lua

  webserver("127.0.0.1:8083", "supersecretpassword", "supersecretAPIkey")

to the configuration, and point your browser at http://127.0.0.1:8083 and log in with any username, and that password. Enjoy!

Security of the Webserver
-------------------------

The built-in webserver serves its content from inside the binary, this means it will not and connot read from disk.

By default, our web server sends some security-related headers::

   X-Content-Type-Options: nosniff
   X-Frame-Options: deny
   X-Permitted-Cross-Domain-Policies: none
   X-XSS-Protection: 1; mode=block
   Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'

You can override those headers, or add custom headers by using the last parameter to :func:`webserver`.
For example, to remove the X-Frame-Options header and add a X-Custom one:

.. code-block:: lua

  webserver("127.0.0.1:8080", "supersecret", "apikey", {["X-Frame-Options"]= "", ["X-Custom"]="custom"}

dnsdist API
-----------

TODO
