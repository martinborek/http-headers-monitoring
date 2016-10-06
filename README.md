# http-headers-monitoring
Application for HTTP headers monitoring, developed for the course "Network Applications and Network Administration", taken at Brno University of Technology in 2014.

Author: Martin Borek

How to run:
```sh
httphdrs.py [-h] (-i I | -f F) -o O [-H H] [-p P]

python2 httphdrs.py --help
sudo python2 httphdrs.py -o output.xml -i p2p1
python2 httphdrs.py -o output.xml -f input.pcap -H Accept-Language,Accept-Encoding -p 80
