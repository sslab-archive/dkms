#!/bin/bash
# use this ./linuxServerTest.sh $serverPrivateKeyFile $startServerKeyIndex $endServerKeyIndex
# server port will be defined by

if [ $# -ne 3 ]; then
	echo "plz input 3 param for this shell."
	echo "bash linuxServerTest.sh [keyFileName] [startIndex] [endIndex]"
	exit 1;
fi

startServerPort=5000

serverPrivateKeyFile=${1}
startServerKeyIndex=${2}
endServerKeyIndex=${3}
myIp=$(hostname -I)[0]

numOfServers=`expr $endServerKeyIndex - $startServerKeyIndex`

curIndex=$startServerKeyIndex
num=0
while [ $curIndex != $endServerKeyIndex ]
do
	serverPrvKey=`awk 'NR==v1' v1=$curIndex $serverPrivateKeyFile`
	curPort=`expr $startServerPort + $num`
	./dkms server runserver --ip=$myIp --port=$curPort --key=$serverPrvKey \
	--log="server_"$curPort > /dev/null &
	curIndex=`expr $curIndex + 1`
	num=`expr $num + 1`
	sleep 1
	echo ""
	echo ""
	echo ""
done
