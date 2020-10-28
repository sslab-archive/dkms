#!/bin/bash
# use this ./linuxServerTest.sh $serverPrivateKeyFile $startServerKeyIndex $endServerKeyIndex
# server port will be defined by

if [ $# -ne 3 ]; then
	echo "plz input 3 param for this shell."
	exit 1;
fi

startServerPort=5000

serverPrivateKeyFile=${1}
startServerKeyIndex=${2}
endServerKeyIndex=${3}
myIp=$(hostname -I)

numOfServers=`expr $endServerKeyIndex - $startServerKeyIndex`

curIndex=$startServerKeyIndex
while [ $curIndex != $endServerKeyIndex ]
do
	serverPrvKey=`awk 'NR==v1' v1=$curIndex $serverPrivateKeyFile`
	curPort=`expr $startServerPort + $curIndex`
	./dkms server runserver --ip=$myIp --port=$curPort --key=$serverPrvKey \
	--log="server_"$curPort &
	curIndex=`expr $curIndex + 1`
	echo ""
	echo ""
	echo ""
done
