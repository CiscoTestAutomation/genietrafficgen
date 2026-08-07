July 2026
==========

July 28 - Genietrafficgen v26.7
-------------------------------



.. csv-table:: New Module Versions
    :header: "Modules", "Version"

    ``genie.trafficgen``, v26.7




Changelogs
^^^^^^^^^^
--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* ixiarestpy
    * Modified IxiaRestPy
        * Fixed ``connect()`` to retry ``NewConfig()`` when IxNetwork server is still loading configuration at startup.
        * Added unit tests for retry success and timeout failure scenarios.

* trex
    * Modified Trex
        * Updated ``check_trex_running()`` to stop any existing TRex process before starting a fresh one.
        * Added unit tests for restart success and stop-failure (timeout) scenarios.


