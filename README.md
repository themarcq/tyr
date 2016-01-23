# tyr
Phone notifications on linux

##Compiling
for server and linux just cd to these directories and make

##Usage
To work it needs server part with known reachable ip.

Then you need to start desktop part (linux directory) and specify ip and port to a server
./bin/tyr -a <ip> -p <port>

then install android app and run it.
To allow notification access go to settings > security > notification access and select tyr
Now open tyr app, on desktop go to ~/.tyr/ and open qrcode.png, and scan it by clicking scan new qrcode

Enjoy :)
