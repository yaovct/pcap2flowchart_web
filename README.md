# pcap2flowchart: the pcap file convert to a flowchart figure with a web mouseover interation.
This program is a server-site program.

The index.html contains two inputs of pcap filename and filtering string.

After post methed activated, the program will read a signaling data with pcap format that contains SIP/RTP/DNS/Diameter/M2UA protocols and convert it to a call trace flowchart figure.

In addition, the mouseover event will be triggered once the signaling data is driven.

You need to install httpd, php-cli, php-gd, wireshark and gnuplot libraries at first. (see install/Dockerfile)

The output filename will be a PNG format with the first timestamp of your_pcap_file.
