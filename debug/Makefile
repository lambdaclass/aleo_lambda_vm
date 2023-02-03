build:
	cargo build --release

valgrind: build
	valgrind --leak-check=full --show-reachable=yes --log-file="${OUTDIR}valgrind.${FN}.txt" ./target/release/lambdavm_debug --f ${FN} 

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

reports:
	tar -zcvf reports.tar.gz reports/
