RENDER - RabbitEars NextGen Data Evaluator Report - v0.1

RENDER is software written using Google Gemini and Anthropic Claude to parse
ATSC 3.0 signals and output them in an HTML format, similar to the TSReader
HTML Export format.  It has been written for the Linux command line, but 
should compile on the Mac with the proper prerequisites and should be 
possible to get working on Windows.

Many thanks to drmpeg; his l1detail parsing code has been adapted for use in
RENDER.  It, like RENDER, is licensed in GPLv3.

https://github.com/drmpeg/dtv-utils/tree/master

The software supports the following input formats:

Packets:
- HDHomeRun Debug
- IPv4-PCAP
- ALP-PCAP

Text:
- HDHomeRun plpinfo format
- HDHomeRun l1detail format
- HDHomeRun TUI text output format

Both the packet data and the text data are needed for full information.  The 
ideal set of information is the ALP-PCAP combined with either the l1detail or
the HDHomeRun TUI text output from an HDHomeRun with the Dev upgrade.  These 
items together should have the same name, and provide all the information 
that the software can currently parse.

It supports or mostly supports the following ATSC 3.0 functions and 
parameters:

- PLP Information (if any Text available)
- L1 Basic and L1 Detail (if l1detail or TUI text/Dev available)
- Link Mapping Table (if ALP-PCAP)
- Service List Table
- Capability Descriptor Table, which is Signal Signing
- Broadcast Positioning System
- ROUTE-based audio/video and data streams
- System Time information
- Basic data usage analysis

These functions are known to be significantly incomplete or non-functional:

- MMT-based audio/video and data streams
- ESG support - Guide data chunks are present but not organized
- Bitrate calculations

To build on Ubuntu, it is believed you'll need these packages:

build-essential
libpcap-dev
libxml2-dev
zlib1g-dev
libssl-dev

To build on RedHat, it is believed you'll need these packages:

libpcap-devel
libxml2-devel
zlib-devel
openssl-devel

And you'll need the HDHomeRun library, but I've included that in the zip file
if you don't already have it installed.

Building RENDER should be as running "make" in the source directory, which 
will produce an executable by that name.

To run RENDER, put a PCAP or debug file in the folder with your executable 
and then create a text file with that same name but ending in .txt which 
contains the PLP info from the HDHomeRun plpinfo command along with, if 
applicable, the l1detail string.  Alternatively, if you're using the latest
HDHomeRun TUI, using the a or z keys to capture a debug or PCAP file should
result in a PCAP and .txt file with the same name that you can use.

Then just run it:

./render <pcap/debug file name>

It'll output an HTML file with the same name that you can then review.  As 
RENDER is currently highly experimental, if any output looks questionable, 
please reach out to me:  webmaster@rabbitears.info

Please also reach out with any questions or comments.  Enjoy this tool!
