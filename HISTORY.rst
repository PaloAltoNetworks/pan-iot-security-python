Release History
===============

0.3.0 (2022-05-16)
------------------

- Add -O option, an optimised version of -j for the get all methods,
  which does not place all the results in memory.

- Add policies_all() method.

- Fix missing profile(), policy() in method attributes documentation.

- Unit test enhancements.

0.2.0 (2022-04-23)
------------------

- Add support for new API requests:

  - Get device profiles
  - Get policy rule recommendations

- Print stack trace entries in addition to exception information
  depending on debug:

  - debug 0: exception information
  - debug 1: stack trace limit=-1
  - debug > 1: stack trace limit=None

- /tag/list API request uses offset and pagelength.

- iotapy.py: Fix for missing await.

0.1.0 (2022-04-09)
------------------

- Change generator methods to return a tuple.  NOTE: not backward
  compatible.  See documentation for the 3 ``*_all()`` methods.

- Documentation fixes and improvements.

- Unit test fixes and improvements.

0.0.0 (2022-03-23)
------------------

- Initial release.
