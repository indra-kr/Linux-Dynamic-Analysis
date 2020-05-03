#!/usr/bin/perl
use Socket;
$server="0.0.0.0";
$port=31337;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);
bind(S,pack_sockaddr_in($port,inet_aton($server)));
listen(S, 5);
$caddr = "";
if($caddr = accept(CS, S)) {
	print "Accepted new client\n";
	while(1) {
		$buf="";
		recv(CS, $buf, 1024, 0);
		if($buf eq "") { last; }
		print "Received: $buf";
	}
	close CS;
}
