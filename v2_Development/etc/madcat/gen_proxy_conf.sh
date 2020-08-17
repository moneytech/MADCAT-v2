#!/bin/bash
echo "tcpproxy = { -- [<listen port>] = { \"<backend IP>\", <backend Port> },"
for i in {10000..20000}
do
   echo "[$i]  = { \"192.168.2.198\", $i },"
done
echo "}"
