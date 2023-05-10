# rbtmalloc  

This project is about the memory allocator which using RBT to sort!  


Development note [rbtmalloc](https://hackmd.io/@wanghanchi/linux2023-rbtmalloc)

- Build  
```shell
$ make
```
  
- Test with shared object  
```shell
$ make
$ ./test_small
$ ./test_large
```  
- Slient the debug information
```shell
$ make DEBUG=0
```



## TODO  

- Implement memory pool for small size allocate
- Implement the recycle mechanism
- Replace the list with RBT in large size memory manage
- Improve the multithread performance
- Migrate the performance benchmark

## Reference 
- [mmap-alloc](https://github.com/mdukat/mmap-malloc)  
- [allocator](https://github.com/thestinger/allocator)
- [isoalloc](https://github.com/struct/isoalloc)