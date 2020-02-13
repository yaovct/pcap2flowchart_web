#!/bin/bash
SiteName='210_Docker'
base_dir='/root/cs210_pcap2flow'
echo 
echo "   Start docker @ \"$SiteName\""
echo
######################
# Application Server #
######################
#docker_app_image='a:1'
docker_app_image='pcap2flow:20200205a'

# mariadb / mysql, user = tl240_db, pass = chttl240
docker run --dns 168.95.1.1 \
           --name CS210.app \
           --rm \
            -v $(pwd):$base_dir \
            -p 80:80 \
            -t $docker_app_image &