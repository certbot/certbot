proto = chocolate.proto

$(proto:.proto=_pb2.py): $(proto)
	protoc $^ --python_out=.

clean:
	rm -f *_pb2.py *_pb2.pyc
