#!/bin/bash
SiteName='Docker'
base_dir='/root/pcap2flowchart_web'
echo 
echo "   Start docker @ \"$SiteName\""
echo
######################
# Application Server #
######################
#docker_app_image='a:1'
docker_app_image='pcap2flow:20200205a'

docker run --name docker.app \
           --rm \
            -v $(pwd):$base_dir \
            -p 80:80 \
            -t $docker_app_image &