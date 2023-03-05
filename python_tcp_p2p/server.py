import threading
import socket
import select
import json
import time
import sys

def get_free_port():  
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.bind(('', 0))
    ip, port = sock.getsockname()
    sock.close()
    return port


server_addr = ('ip',80)
server_secret = 'test'
name = 'test'
secret = 'test'
service_port = 30000
sign = b'Vb4Q'
keep_alive_list = []
status = True

def keep_alive():
	global keep_alive_list,status
	while True:
		if status == False:
			print('KeepAlive Exit.')
			sys.exit()
		for s in keep_alive_list:
			try:
				s.sendall(sign+sign)
			except Exception:
				pass
		time.sleep(3)


def unpack_data(data,buff_data):
	global sign
	data_list = []
	data = buff_data + data 
	count = data.count(sign)
	if count < 1:
		return data_list,data
	elif count == 1:
		data = data[data.find(sign,0):]
		return data_list,data
	else:
		data = data[data.find(sign,0):]
	o = True
	if count % 2 != 0:
		o = False
		count -= 1
	counta = 0
	index = 0
	while counta <= count-1:
		b = data.find(sign,index+1)
		msg = data[data.find(sign,index)+len(sign):b]
		index = b 

		if msg == b'':
			counta += 1
			continue
		data_list.append(msg)
		counta += 1
	if o == True:
		buff_data = data[data.rfind(sign)+len(sign):]
	else:
		buff_data = sign + data[data.rfind(sign)+len(sign):]
	return data_list,buff_data

def socket_close(l):
	global keep_alive_list
	for s in l:
		try:
			socket.close()
		except Exception:
			pass
		try:
			keep_alive_list.remove(s)
		except Exception:
			pass

def data_exchange_server(service_port,p2p_socket):
	global sign,keep_alive_list,connect_socket,status
	keep_alive_list.append(p2p_socket)
	buff_data = b''
	data_list = []
	target = ('127.0.0.1',service_port)
	p2p_socket.setblocking(False)
	while True:
		r,w,e = select.select([p2p_socket],[],[])
		if status == False:
			socket_close((p2p_socket,))
			sys.exit()
		try:
			msg = p2p_socket.recv(2048)
		except ConnectionResetError:
			msg = b''
		if msg == b'':
			socket_close((p2p_socket,))
			print('P2P隧道关闭.')
			return False
		data_list,buff_data = unpack_data(msg,buff_data)
		for msg in data_list:
			connect_socket.sendto(msg,target)
		if len(buff_data) > 10240:
			buff_data = b''
			print('Error.')



def p2p_tcp(target_name,start_time,method,port):

	if method == 'client':
		res = send_p2p_request()
		if res == False:
			return False
		else:
			target = res[0]
			port = res[1]
	else:
		target = target_name
	print(target)
	while True:
		if time.time() > start_time:
			break
	p2pL = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	p2pC = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

	p2pL.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	p2pC.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	p2pL.bind(('0.0.0.0',port))
	p2pC.bind(('0.0.0.0',port))
	p2pL.setblocking(False)
	p2pC.setblocking(False)
	p2pL.listen(1)


	start_time = time.time()
	while time.time() - start_time < 15:

		try:
			p2pC.connect(target)
		except Exception:
			pass
		else:
			print("P2P 连接成功.")
			return p2pC

		try:
			p2pL.accept()
		except Exception:
			pass
		else:
			print("P2P 接收连接.")
			return p2pL

	print('P2P 失败.')
	socket_close((p2pL,p2pC))
	return False

def handle_server():
	global name,server_secret,secret,keep_alive_list
	data = json.dumps({
			'type':'reg',
			'name':name,
			'secret':secret,
			'server_secret':server_secret
		}).encode()
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	try:
		s.connect(server_addr)
	except Exception:
		print('服务端连接失败.')
		socket_close((s,))
		return False
	s.setblocking(False)
	while True:
		try:
			s.sendall(data)
		except Exception:
			print('登记请求发送失败.')
			socket_close((s,))
			return False
		try:
			msg = s.recv(1024)
		except Exception:
			time.sleep(3)
		else:
			if msg == b'':
				print('服务端连接已断开.')
				socket_close((s,))
				return False
			else:
				try:
					target = tuple(json.loads(msg.decode()))
				except Exception:
					time.sleep(2)
				else:
					port = s.getsockname()[1]
					return port,target

def create_tunnel(target,start_time,method,port,service_port):
	p2p_socket = p2p_tcp(target,start_time,method,port)
	if p2p_socket == False:
		return False
	else:
		data_exchange_server(service_port,p2p_socket)

def handle_p2p():
	global connect_socket,keep_alive_list,service_port,status
	count = 0
	data = b''
	while True:
		r,w,e = select.select([connect_socket],[],[])
		if status == False:
			break
		if data == b'':
			try:
				data,addr = connect_socket.recvfrom(2048)
			except Exception:
				break
			if addr != ('127.0.0.1',service_port):
				data = b''
				continue
		try:
			#print(keep_alive_list[count])
			keep_alive_list[count].sendall(sign+data+sign)
		except (ConnectionResetError,IndexError):
			pass
		except Exception:
			data = b''
		else:
			data = b''
		count += 1
		if count == len(keep_alive_list):
			count = 0



def main():
	res = handle_server()
	if res == False:
		return False
	else:
		port = res[0]
		target = res[1]
	thread = threading.Thread(target=create_tunnel,args=(target,time.time()+1,'server',port,service_port))
	thread.start()



if __name__ == "__main__":
	connect_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	connect_socket.setblocking(False)
	keep = threading.Thread(target=keep_alive)
	keep.start()
	handle = threading.Thread(target=handle_p2p)
	handle.start()
	try:
		while True:
			main()
			time.sleep(5)
	except Exception as ex:
		print('\n'+ex+'\n')
	except KeyboardInterrupt:
		print('\nExit.')
	status = False
	time.sleep(3)
	connect_socket.close()


