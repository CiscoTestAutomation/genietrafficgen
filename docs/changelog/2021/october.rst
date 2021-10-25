--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* pagent
    * Clean read buffer after using sendline() and expect()
    * no shutdown interface when start packet counts
    * support port list for api start_pkt_count_rawip, start_pkt_count_rawipv6, stop_pkt_count
    * adding send packets per seconds argument

* trex
    * support port list for api start_pkt_count_rawip, start_pkt_count_rawipv6, stop_pkt_count
    * enable promiscuous mode on ports when start the packet count
    * adding send packets per seconds argument


