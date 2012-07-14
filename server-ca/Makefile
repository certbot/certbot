# deploy: chocolate_protocol_pb2.py chocolate.py CSR.py daemon.py CA.sh
#	scp chocolate_protocol.proto chocolate.py CSR.py daemon.py CA.sh ${CHOCOLATESERVER}:
#	ssh ${CHOCOLATESERVER} protoc chocolate_protocol.proto --python_out=.
#	rsync -av --delete sni_challenge demoCA ${CHOCOLATESERVER}:
#	ssh ${CHOCOLATESERVER} make -C sni_challenge clean all

chocolate_protocol_pb2.py: chocolate_protocol.proto
	protoc chocolate_protocol.proto --python_out=.
	cp -p chocolate_protocol_pb2.py ../client-webserver/

clean:
	rm -f *.pyc
