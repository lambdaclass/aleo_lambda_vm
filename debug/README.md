# lambdavm Debug

## 1. Run Valgrind

### 1.1 Running Valgrind on a single test function

Running the following will run `valgrind` for a particular test function defined in `debug/src/main.rs`:

```
make valgrind FN=test_function_name
```

These test functions, for now at least, just run the `main.aleo` program in the `programs/add/` calling all its different functions. As an example, you can run the first one, `test01_add_with_u16_public_inputs`, by doing

```
make valgrind FN=test01_add_with_u16_public_inputs
```

### 1.2 Running Valgrind on every test function

Running the following will run `valgrind` for every function supported in `main.rs` and log the result in a separate file for each function

```
make valgrind-full
```

### 1.3 Cleaning

Run `make clean-valgrind` to clean your dir of Valgrind files.

## 2. Run Heaptrack

### 2.1 Running Heaptrack on a single test function

Running the following will run `heaptrack` for a particular function that has to be supported in `main.rs` and log the result in a separate file for it

```
make heaptrack FN=test_function_name
```

### 2.2 Running Heaptrack on every test function

Running the following will run `heaptrack` for every function supported in `main.rs` and log the result in a separate file for each function

```
make heaptrack-full
```

### 2.3 Cleaning

Run `make clean-heaptrack` to clean your dir of heaptrack files.

## 3. Adding more test functions to profile

If you want to add a function to profile follow these steps:

1. Implement the function in `main.rs`.
2. Add the function execution to the `match`.
3. Add the function name to the functions names list in `valgrind-full.sh`

And that's it!
