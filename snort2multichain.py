import time
import subprocess
import select
import mcrpc
import socket

f = subprocess.Popen(['tail','-F','/var/log/snort/alert'],\
        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)
client = mcrpc.RpcClient('127.0.0.1', '6736', 'test', 'test')
info = client.getinfo()
stream = "snort"
print (info)
hostname = socket.gethostname()
ipAddress = socket.gethostbyname(hostname)
print (hostname)
#client.create("stream", stream, True)
while True:
	if p.poll(1):
		s = f.stdout.readline()
		txid = client.publish(stream, hostname, {"text": s})
		client.subscribe(stream)
		resp = client.getstreamitem(stream, txid)
		s = resp["data"]["text"]
		log = 'Transaction Id : '
		print (log)
		print (txid)
