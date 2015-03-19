all:
	./build.sh

test:
	./build.sh _all

clean:
	rm -f *.c *.so
	rm -rf __pycache__
