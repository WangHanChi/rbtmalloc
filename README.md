# rbtmalloc  

This project is about the memory allocator which using RBT to sort!  

- Build  
```shell
$ make
```
  
- test with shared object  
```shell
$ make test
```
  
- Replace sbrk with mmap  
```shell
$ make test MMAP=1
```
  

## Reference 
- [mmap-alloc](https://github.com/mdukat/mmap-malloc)  