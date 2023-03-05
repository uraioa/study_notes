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

tunnel_count = 1
server_addr = ('ip',80)
server_secret = ''
target_name = ''
target_secret = ''

listen_port = 1072
sign = b'Vb4Q'
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
		time.sleep(1)


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




def data_exchange_client(p2p_socket):
	global sign,keep_alive_list,listener,target
	keep_alive_list.append(p2p_socket)
	buff_data = b''
	data_list = []

	p2p_socket.setblocking(False)
	while True:
		r,w,e = select.select([p2p_socket],[],[])
		if status == False:
			socket_close((p2p_socket,))
			return False
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
			listener.sendto(msg,target)
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
	for a in [p2pC,p2pL]:
		a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		a.bind(('0.0.0.0',port))
		a.setblocking(False)
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

def send_p2p_request():
	global server_addr,server_secret,target_name,target_secret
	port = get_free_port()
	data = json.dumps({
			'type':'p2p',
			'server_secret':server_secret,
			'target_secret':target_secret,
			'target_name':target_name
		}).encode()
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(('0.0.0.0',port))
	try:
		s.connect(server_addr)
		s.sendall(data)
	except Exception:
		print('服务端连接失败.')
		socket_close((s,))
		return False
	s.setblocking(False)
	try:
		time.sleep(5)
		msg = s.recv(1024)
	except Exception:
		print('请求超时.')
		socket_close((s,))
		return False

	if msg == b'' or msg == b'Fail.':
		print('请求失败.')
		socket_close((s,))
		return False

	return tuple(json.loads(msg.decode())),port

def handle_p2p():
	global listener,keep_alive_list,status,target
	count = 0
	data = b''
	r,w,e = select.select([listener],[],[])
	data,target = listener.recvfrom(2048)

	while True:
		r,w,e = select.select([listener],[],[])
		if status == False:
			break
		if data == b'':
			try:
				data,addr = listener.recvfrom(2048)
				if addr != target:
					data = b''
					continue
			except Exception:
				break
		try:
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
	global keep_alive_list,tunnel_count
	if len(keep_alive_list) == tunnel_count:
		return False
	p2p_socket = p2p_tcp(target_name,time.time()+1.5,'client',0)
	if p2p_socket == False:
		return False
	t = threading.Thread(target=data_exchange_client,args=(p2p_socket,))
	t.start()



if __name__ == "__main__":
	keep_alive_list = []
	target = ('127.0.0.1',10)
	listener = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	listener.setblocking(False)
	listener.bind(('127.0.0.1',listen_port))
	keep = threading.Thread(target=keep_alive)
	keep.start()
	handle = threading.Thread(target=handle_p2p)
	handle.start()
	try:
		while True:
			main()
			time.sleep(5)
	except Exception as ex:
		print(ex)
	except KeyboardInterrupt:
		print('\nExit.')
	status = False
	time.sleep(3)
	listener.close()
