build:
	cargo build --release

valgrind: build
	valgrind --leak-check=full --show-reachable=yes --log-file="valgrind.${FN}.txt" ./target/release/vmtropy_debug --f ${FN} 

valgrind-full: build
	./valgrind-full.sh

clean-valgrind:
	rm valgrind.*.txt

heaptrack-full: build
	./heaptrack-full.sh

clean-heaptrack:
	rm heaptrack.*.gz heaptrack.*.txt

profile-full:
	heaptrack-full
	valgrind-full