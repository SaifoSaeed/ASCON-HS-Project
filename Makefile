.PHONY: clean build run all

all: loop
loop:
	rm -rf perm_vectors.txt
	@for i in $$(seq 0 $(RUNS)); do \
		echo "Running target iteration $$i"; \
		cargo run --manifest-path SW/Cargo.toml --release -- $$i; \
		mv vectors.txt HW/vectors.txt; \
		$(MAKE) -C HW SIM=verilator TESTCASE=test_rust_vectors; \
	done

run_all: run
	mv vectors.txt HW/vectors.txt
	$(MAKE) -C HW SIM=verilator TESTCASE=test_rust_vectors

run:
	cargo run	--manifest-path SW/Cargo.toml --release

build:
	cargo build	--manifest-path SW/Cargo.toml --release

clean:
	cargo clean	--manifest-path SW/Cargo.toml