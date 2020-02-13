FROM centos:7
MAINTAINER yaovct@cht.com.tw

RUN export http_proxy=http://10.144.169.125:8080
RUN export https_proxy=http://10.144.169.125:8080
RUN export ftp_proxy=http://10.144.169.125:8080

RUN yum update -y
RUN yum install php-cli php-gd gnuplot wireshark -y

WORKDIR /cs210_pcap2flow
