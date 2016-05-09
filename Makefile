all:
	./build.sh

test:
	./build.sh _all

clean:
	rm -f *.c *.so
	rm -rf __pycache__
	rm -f maalstroom/*.c maalstroom/*.so
	rm -rf maalstroom/__pycache__
