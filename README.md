# memalloc - Memory Allocator/Garbage Collector

memalloc is a practice project focused on creating a custom memory allocator/garbage collector in C. Initially inspired by a tutorial from Dmitri Soshnikov, I revamped the design to make it more comprehensible, implement garbage collection, and better suited to support the rest of my ML stack.

**Highlights:**
- Fundamental module in the six-part ML stack.
- Provides the memory management backbone for projects like zot.
- Built using CMake.
- Originally based on Dmitri Soshnikov’s tutorial.

## Getting Started

Clone the repository and build:
```bash
git clone https://github.com/iudah/memalloc.git
cd memalloc
cmake -S . -B /build
cmake --build ./build
```

## Resources

For further details on the inspiration behind this project, check out Dmitri Soshnikov’s tutorial: [Writing a Memory Allocator](http://dmitrysoshnikov.com/compilers/writing-a-memory-allocator/).

## Feedback

Please open an issue for any feedback or suggestions.
