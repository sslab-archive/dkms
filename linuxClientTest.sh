#!/bin/bash

if [ $# -ne 5 ]; then
	echo "plz input 5 param for this shell"
	echo "bash linuxClientTest.sh [clientKeyFile] [serverNum] [clientIndex] [t] [u]"
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
		addrStr=$addrStr","$ip:$port
		registeredNum=`expr $registeredNum + 1`
		if [ $registeredNum -eq $serverNum ]; then
			break 2
		fi
	done
done

addrStr=${addrStr:1}
userId="user"$clientIndex
clientPrvKey=`awk 'NR==v1' v1=$clientIndex $clientPrivateKeyFile`
./dkms client register $userId $clientPrvKey $addrStr --t=$t --u=$u


echo "Finish registered.. now register to checker"
sleep 3

./dkms client check $userId $addrStr

echo "Finish register to checker.. now start checker daemon"

sleep 3

startCheckerNum=0
for elem in "${serverInfoList[@]}"
do
	data=(${elem[0]})
	ip=${data[0]}
	num=${data[1]}
	for i in $(seq 0 $num);
	do
		port=`expr $startServerPort + $i`
		./dkms server startChecker --ip=$ip --port=$port
		startCheckerNum=`expr $startCheckerNum + 1`
		if [ $startCheckerNum -eq $serverNum ]; then
			break 2
		fi
	done
done

