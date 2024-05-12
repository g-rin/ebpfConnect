Attempt to load the eBPF program leads to an unreadable verifier's error.

- log.txt - contains the log of the following command (behalf of 'root')
	`make && ./ebpf-loader --obj connect.btf.o > log.txt 2>&1`
    
- environment.txt - contains info about toolset and environment where
	the problem is reproducing.

- connect.bpf.c - a copy of a part of my project which reproduces the problem.

- ebpf_loder.cpp - yet another copy of userspace code of my project.

