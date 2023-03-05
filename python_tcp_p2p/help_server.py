import socket
import select
import json
import time
import sys
import os

bind_addr = ('0.0.0.0',30001)
server_secret = ''
serverD = {}
connL = []

def handle_msg(conn,msg):
	global serverD,connL
	try:
		msg = json.loads(msg.decode())
	except Exception:
		pass
	print(msg)
	try:
		if msg['server_secret'] != server_secret:
			return 'Server secret 认证失败.'
		if msg['type'] == 'p2p':
			print('p2p')
			try:
				target = serverD[msg['target_name']]
				if msg['target_secret'] != target['secret']:
					return 'Target secret 认证失败.'
			except Exception:
				conn.sendall(b'Fail.')
				conn.close()
				connL.remove(conn)
				return 'Target 查询失败.'

			try:
				target['socket'].sendall(json.dumps(conn.getpeername()).encode())
				conn.sendall(json.dumps(target['socket'].getpeername()).encode())
			except Exception as ex:
				del serverD[msg['target_name']]
				print(f'\n\n{ex}\n\n')
				return 'P2P 请求发送失败.'

		elif msg['type'] == 'reg':
			try:
				serverD[msg['name']] = {}
				serverD[msg['name']]['socket'] = conn
				serverD[msg['name']]['last'] = time.time()
				serverD[msg['name']]['secret'] = msg['secret']
				print(f"{msg['name']} 登记成功.")

			except Exception as ex:
				print(ex)
				try:
					del serverD[msg['name']]
				except Exception:
					return False
	except Exception as ex:
		print(ex)
		return False

def clean_time_out():
	for server in list(serverD.keys()):
		if time.time() - server['last'] > 10:
			del serverD[server]

def start():
	global connL
	main_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	main_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	main_socket.bind(bind_addr)
	main_socket.listen(600)
	main_socket.setblocking(False)

	while True:
		r,w,e = select.select([main_socket]+connL,[],[])
		for s in r:
			if s == main_socket:
				conn,addr = main_socket.accept()
				connL.append(conn)
			else:
				msg = s.recv(1024)
				if msg == b'':
					s.close()
					connL.remove(s)
				else:
					print(handle_msg(s,msg))

if __name__ == "__main__":
	start()


