# STLD-Demo
This is a header-only library. It does not need to be installed. Just clone the repo with  
`git clone https://github.com/zuan-wang/STLD.git`

Next, compile the project as follows:
- Create a directory named build.
- Execute the command “cmake PATH” in the build directory to generate a Makefile (PATH is the directory where CMakeLists.txt is located).
- Use the command "make" to compile.

Next, run STLD as follows:
- Run certificate authority (CA) to produce a key pair <pk, sk> via:  
`./build/main ca 1024`

- Run the main program via:  
`./build/main anti_2_1000_rtree_3.txt query_anti_3.txt nopt`

- Run the optimized version of the main program via:  
`./build/main anti_2_1000_rtree_3.txt query_anti_3.txt opt`
