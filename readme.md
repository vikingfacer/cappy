
# Cappy _the crappy network capture_
![ci](https://github.com/vikingfacer/cappy/actions/workflows/ci.yml/badge.svg)

![CappyImage](img/cappy1.jpg)

Cappy is 🚧 (WORK IN PROGRESS)

Cappy is a network capture project. The goal is to create something that can
(crappily) filter / capture network traffic and also allow the user to load pcap programs


The cappy arguments
* list of devices is display (or not)
    * -l _or_ --list: list devices

* device or file is opened
    * -d _or_ --device: open device
    * -i _or_ --input: open file
    * _These are mutual exclusive_
    * but if neither are given the "any" device is used

* program dispatched or output packet capture
    * -p _or_ --program: dispatch program on open capture (or display packets)
        * _This takes a special format argument_ library:function

* Output capture to file
    * -o _or_ --output: file capture is saved to

* filter capture traffic
    * positional arguments using the tcpdump filter spec

```
cappy -l
      -[d|i] [device|lookatthiscap.pcap]
      -p libCap.so:TheCappestFunction
      -o whatthecap.pcap
      proto == tcp`
```
