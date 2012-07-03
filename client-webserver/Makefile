deploy: chocolate_protocol_pb2.py chocolate.py CSR.py pkcs10.py daemon.py
	scp chocolate_protocol.proto chocolate.py CSR.py pkcs10.py daemon.py ${CHOCOLATESERVER}: && ssh ${CHOCOLATESERVER} protoc chocolate_protocol.proto --python_out=.

chocolate_protocol_pb2.py: chocolate_protocol.proto
	protoc chocolate_protocol.proto --python_out=.

clean:
	rm -f *.pyc
