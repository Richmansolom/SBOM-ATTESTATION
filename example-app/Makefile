# Thin wrapper for CI: `make -C example-app` builds libpng via CMake.
# Libpng upstream uses CMakeLists.txt (see project root here).
.PHONY: all clean

CMAKE_FLAGS ?= -DCMAKE_BUILD_TYPE=Release

all:
	cmake -S . -B build $(CMAKE_FLAGS)
	cmake --build build --parallel

clean:
	rm -rf build
