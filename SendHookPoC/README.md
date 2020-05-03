# SendHookPoC

A PoC code for hooking the send syscall by ptrace on the 32/64bit machines.  
This program was a private pilot project for the PoC of dynamic analysis about mobile applications.  
See [Regarding of analysis methodology on the mobile applications](https://teamcrak.tistory.com/377)

### 32bit machine
```sh
[indra@CentOS5 H00K]$ cat cli.pl
#!/usr/bin/perl
use Socket;
$server="127.0.0.1";
$port=31337;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));

if(connect(S,sockaddr_in($port,inet_aton($server)))) {
	while(1) {
		$buf=<STDIN>; chomp $buf;
		send(S, $buf."\n", 1024);
	}
	close(S);
}
[indra@CentOS5 H00K]$ nc -lvvp 31337 &
[1] 14449
[indra@CentOS5 H00K]$ listening on [any] 31337 ...

[indra@CentOS5 H00K]$ ./cli.pl &
[2] 14450
[indra@CentOS5 H00K]$ connect to [127.0.0.1] from CentOS5.3 [127.0.0.1] 57569


[2]+  Stopped                 ./cli.pl
[indra@CentOS5 H00K]$ ./1 14450 dog cat &
[3] 14451
[indra@CentOS5 H00K]$ fg 2
./cli.pl
test
----- Original Memory (5 bytes)
00000000  74 65 73 74 0A                                        test.

----- Original Memory
test
----- Original Memory (5 bytes)
00000000  74 65 73 74 0A                                        test.

----- Original Memory
This is a dog
----- Original Memory (14 bytes)
00000000  54 68 69 73 20 69 73 20 61 20 64 6F 67 0A             This is a dog.

----- Original Memory
----- Modified Memory (14 bytes)
00000000  54 68 69 73 20 69 73 20 61 20 63 61 74 0A             This is a cat.

----- Modified Memory
This is a cat   # <<<<<<<<<< Changed Message
----- Original Memory (14 bytes)
00000000  54 68 69 73 20 69 73 20 61 20 63 61 74 0A             This is a cat.

----- Original Memory
^X
```

### 64bit machine
```sh
[indra@CentOS7 H00K]$ cat cli.pl
#!/usr/bin/perl
use Socket;
$server="172.16.138.51";
$port=31337;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));

if(connect(S,sockaddr_in($port,inet_aton($server)))) {
	while(1) {
		$buf=<STDIN>; chomp $buf;
		send(S, $buf."\n", 1024);
	}
	close(S);
}
[indra@CentOS7 H00K]$ ./serv.pl &
[1] 69340
[indra@CentOS7 H00K]$ ./cli.pl &
[2] 69341
[indra@CentOS7 H00K]$ Accepted new client


[2]+  Stopped                 ./cli.pl
[indra@CentOS7 H00K]$ ./1 69341 dog cat &
[3] 69342
[indra@CentOS7 H00K]$ fg 2
./cli.pl
test
----- Original Memory (5 bytes)
00000000  74 65 73 74 0A                                        test.

----- Original Memory
Received: test
----- Original Memory (5 bytes)
00000000  74 65 73 74 0A                                        test.

----- Original Memory
This is a dog.
----- Original Memory (15 bytes)
00000000  54 68 69 73 20 69 73 20 61 20 64 6F 67 2E 0A          This is a dog..

----- Original Memory
----- Modified Memory (15 bytes)
00000000  54 68 69 73 20 69 73 20 61 20 63 61 74 2E 0A          This is a cat..

----- Modified Memory
Received: This is a cat.   # <<<<<<<<<< Changed Message
----- Original Memory (15 bytes)
00000000  54 68 69 73 20 69 73 20 61 20 63 61 74 2E 0A          This is a cat..

----- Original Memory
^C^C
```
