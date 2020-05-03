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
