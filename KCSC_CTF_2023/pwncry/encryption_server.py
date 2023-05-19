#!/usr/bin/python3

import socket
import threading
import sys
import select
import math
import struct
try:
	from Crypto.Util.number import getPrime
except:
	import os
	os.system("python3 -m pip install pycryptodome")
	from Crypto.Util.number import getPrime

IP = '127.0.0.1'
PORT = 8888
SIZE = 4096
FORMAT = 'utf-8'

def handle_client(conn, addr):
	if 'DEBUG' in sys.argv:
		print(f"[+] Connection received on {addr[0]}:{addr[1]}")
	connected = True
	while connected:
		msg = conn.recv(SIZE).decode(FORMAT)
		if msg and ('<START>' in msg and '<END>' in msg):
			if 'DEBUG' in sys.argv:
				print("\tClient:", msg)
			if 'ENCRYPT' in msg:
				msg = msg.strip()[ msg.index("<START>") + 7 : msg.index("<END>") ].split('-')
				res = pow(int(msg[1]), int(msg[2]), int(msg[3]))

				msg = b'<START>' + str(res).encode() + b'<END>'
				conn.send(msg)
				if 'DEBUG' in sys.argv:
					print("\tServer reply:", msg.decode())
				connected = False
			elif 'GENKEY' in msg:
				p = getPrime(32)
				q = getPrime(32)
				n = p*q
				phi = (p-1)*(q-1)
				e = 7
				while math.gcd(e, phi) != 1:
					e += 1

				msg = f'<START>{n}-{e}<END>'.encode()
				conn.send(msg)
				if 'DEBUG' in sys.argv:
					print("\tServer:", msg.decode())
				connected = False
		elif not msg:
			connected = False

	conn.shutdown(socket.SHUT_RDWR)
	conn.close()
	if 'DEBUG' in sys.argv:
		print(f"[*] Client {addr[0]}:{addr[1]} disconnected")

def main():
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((IP, PORT))
	server.listen()
	if 'DEBUG' in sys.argv:
		print(f"[*] Listening on {IP}:{PORT}...")
	while True:
		try:
			conn, addr = server.accept()
		except KeyboardInterrupt:
			if 'DEBUG' in sys.argv:
				print(f"[*] Shutting down...")
			server.shutdown(socket.SHUT_RDWR)
			server.close()
			break
		thread = threading.Thread(target=handle_client, args=(conn, addr, ))
		thread.start()

if __name__=='__main__':
	main()