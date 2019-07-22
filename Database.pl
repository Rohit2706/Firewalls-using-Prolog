
/*                      LOGIC ASSIGNMENT
                           FIREWALLS

                            DATABASE
*/

lex(X,ad_id) :- member(X,["A","B","C","D","E","F","G","H"]).

lex(X,vlan_id) :- number_string(_,X).

lex(X,allowed_protocol) :- member(X,["tcp","udp","ftp","smtp","http","pop","ntp","0x0800","0x86DD"]).

lex(X,blocked_protocol) :-  member(X,["arp","aarp","atalk","ipx","mpls","netbui","pppoe","rarp","sna","xns"]).

lex(X,tcp_id):- number_string(N,X),
                between(0,65535,N).

lex(X,blocked_tcp) :-  member(X,["67","89","5","557","0x7DD"]).

lex(X,icmp_id_type):- number_string(N,X),
		     ( between(0,43,N);
                       between(253,255,N)).

lex(X,icmp_both_id_code):- number_string(N,X),
                           between(0,16,N).

lex(X,ipaddress) :- number_string(N,X),
                    between(0,255,N).

lex(X,ipv4_source) :- member(X,["67.85.45.76","156.46.45.6","60.35.5.26","6.90.0.33.14/9"]).

lex(X,ipv4_dest) :- member(X,["134.34.23.73","15.43.42.45","0.24.54.126","46.90.10.33.12/7"]).

lex(X,icmp_v6_id_type):- number_string(N,X),
                        ( between(0,4,N);
                          between(100,101,N);
                          between(127,161,N);
                          between(200,201,N)).

lex(X,sub_ipv6) :- member(X,[0,1,2,3,4,5,6,7,8,9,'A','B','C','D','E','F']).

lex(X,ipv6_source) :- member(X,["0::3324:6642:4321:0:7654:0987","1346:7532:9743:2467:0::8532:0934"]).

lex(X,ipv6_dest) :- member(X,["5537:3563:2573:2573:2674:2434:2743:7452/43"]).




