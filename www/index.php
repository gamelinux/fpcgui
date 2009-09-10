<?php

print "

PoC should support two input methods for carving pcaps:
  One is a direct query in the url:
   http://fpcgui.somehost.net/get_pcap.php?bpf=\"host 74.50.87.122 and host 80.30.200.100 and port 80 and port 56640 and proto 6\"
   This would serve you the pcap ready for download... may take some time though :)

  Secound is a webpage that you can enter parameters to carve :
  * DATE, ie 2009-09-09 (this will limit the search to /nsm_data/hostname/dailylogs/2009-09-09/ etc
  * src_host (+ dst_host) OR host1 (+ host2)
  * src_port (+ dst_port) OR port1 (+ port2)
  * protocol

The webpage should also be able to search up connections from sancp data from the db:
  * DATE, this could be a range! default $today
  * src_host (+ dst_host) OR host1 (+ host2)
  * src_port (+ dst_port) OR port1 (+ port2)
  * protocol
  Clicking on the connection, will carve the connection out for download

Mark: some fields can be blank

";

?>
