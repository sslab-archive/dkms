#!/bin/bash

if [ $# -ne 5 ]; then
	echo "plz input 3 param for this shell"
	exit 1;
fi

clientPrivateKeyFile=${1}
serverNum=${2}
clientIndex=${3}
t=${4}
u=${5}

startServerPort=5000
serverInfoList=("141.223.121.163 12"
"141.223.121.164 8")

registeredNum=0
addrStr=""
for elem in "${serverInfoList[@]}"
do
	data=(${elem[0]})
	ip=${data[0]}
	num=${data[1]}
	for i in $(seq 0 $num);
	do
		port=`expr $startServerPort + $i`
		addrStr=$addrStr,$ip:$port
		registeredNum=`expr $registeredNum + 1`
		if [ $registeredNum -eq $serverNum ]; then
			break 2
		fi
	done
done


userId="user"$clientIndex
clientPrvKey=`awk 'NR==v1' v1=$clientIndex $clientPrivateKeyFile`
./dkms client register $userId $clientPrvKey $addrStr


echo "Finish registered.. now start checker"

./dkms client check $userId $addrStr
