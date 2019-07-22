
/*                      LOGIC ASSIGNMENT
                           FIREWALLS
*/

% Important Predicates:-

% The member of a list predicate

member(Head,[Head|_]).
member(X,[_|Tail]) :- member(X,Tail).

% The predicate checks for some clause for every member in the list.

check_list([],_).
check_list([X|List],Clause):-( check(X,Clause);
                               range_of_values(X,Clause)),
                               check_list(List,Clause).


/* Grammar to check a valid Expression for some Clause.

   An Expression is valid if it is one of the following forms-
   * 'any'
   * <value>                                    - literal
   * <value1>,<value2>                          - comma_seperated
   * <value1>-<value2> where value1 < value2.   - range_of_values

   The predicate check checks whether the given Input satisfies a
   particular clause.
*/

expression(Input,Clause) :-  (Input=="any");
                             literal(Input,Clause);
                             comma_separated(Input,Clause);
                             range_of_values(Input,Clause).

literal(Input,Clause):-  check(Input,Clause).

comma_separated(Input,Clause) :-  split_string(Input, ',','', List),
                                  check_list(List,Clause).


range_of_values(Input,Clause) :-  split_string(Input, '-',' ', [X1,X2]),
                                  X1@<X2,
                                  check(X1,Clause),
                                  check(X2,Clause).


/* 1.The Adapter Clause
   Only the packets with the following ids are allowed-
   * Any literal l from A to H or a special atom s = 'any'.
   * C1,C2 where C1,C2 are literals between A and H.
   * C1-C2 ie a range of lliterals.

   ad_id denotes Adapter ID.
*/

check(X,ad_id) :- lex(X,ad_id).

adapter(Input) :- expression(Input,ad_id).

/* 2. The Ethernet Clause
      * All the packets that are VLAN identifiers are allowed provided
        their VLAN constant is a decimal, octal or hexadecimal number.
      * Only the following protocols are allowed-
         tcp,udp,ftp,smtp,http,pop,ntp, 0x0800, 0x86dd.
      * The following protocols are blocked-
         arp,aarp,atalk,ipx,mpls,netbui,pppoe,rarp,sna,xns.

      Type can be either 'VLAN' or 'Protocol'.
*/
check(X,vlan_id) :- lex(X,vlan_id).

ethernet([Type,Id]) :- ( Type == "VLAN",
                         expression(Id,vlan_id));
                       ( Type == "Protocol",
                         lex(Id,allowed_protocol)).

blocked_ethernet([Type,Id]) :- ( Type == "Protocol",
                                 lex(Id,blocked_protocol)).

/* 3.The IPv4 Clause
   Only the packets that satisfy the following conditions are allowed-
   * TCP/UDP conditions
   * ICMP conditions
   * IP addresses

*/

% TCP/UDP conditions

check(X,tcp_id):- lex(X,tcp_id).

tcp(Input):- expression(Input,tcp_id).

blocked_tcp(Input) :- lex(Input,blocked_tcp).

% ICMP conditions

check(X,icmp_id_type):- lex(X,icmp_id_type).

icmp_type(Input):- expression(Input,icmp_id_type).

check(X,icmp_both_id_code):- lex(X,icmp_both_id_code).

icmp_both_code(Input):- expression(Input,icmp_both_id_code).

icmpv4(Type,Code) :- icmp_type(Type),
                     icmp_both_code(Code).

% IP clause

check(X,ipaddress) :- lex(X,ipaddress).

dot_separated(Input,Clause):- split_string(Input, '.',' ', List),
			      check_list(List,Clause).

netmask_condition(Input,ipaddress):- split_string(Input,'/',' ',[X1,X2]),
                                     number_string(N,X2),
                                     between(1,32,N),
                                     dot_separated(X1,ipaddress).

ipclause(Input) :- netmask_condition(Input,ipaddress);
                   dot_separated(Input,ipaddress).

blocked_ipclause(Input,Clause) :- lex(Input,Clause).

ipv4([TCP,[Type,Code],[IPaddress_Source,IPaddress_Dest]]):- tcp(TCP),
                                                            icmpv4(Type,Code),
                                                            ipclause(IPaddress_Source),
                                                            ipclause(IPaddress_Dest),
                                                            not(blocked_ipv4([TCP,_,[IPaddress_Source,IPaddress_Dest]])).

blocked_ipv4([TCP,_,[IPaddress_Source,IPaddress_Dest]]) :- blocked_tcp(TCP);
                                                           blocked_ipclause(IPaddress_Source,ipv4_source);
                                                           blocked_ipclause(IPaddress_Dest,ipv4_dest).

/* 4.The IPv6 Clause
   Only the packets that satisfy the following conditions are allowed-
   * TCP/UDP conditions
   * ICMPv6 conditions
   * IPv6 addresses

*/

% ICMPv6 conditions

check(X,icmp_v6_id_type):- lex(X,icmp_v6_id_type).

icmp_v6_type(Input):- (Input=='any');
                       expression(Input,icmp_v6_id_type).

icmpv6(Type,Code) :- icmp_v6_type(Type),
                     icmp_both_code(Code).

% IPv6 Addresses

check(X,sub_ipv6):- sequence_of_four(sub_ipv6,[X],[]).

check(X,ipv6):- colon_separated(X,ipv6).

colon_separated(Input,ipv6):- split_string(Input, ':' , ' ', List),
		              check_list(List,sub_ipv6).

sequence_of_four(Clause) --> [Z],
			     {( (Z=="0"; Z=="")->W="0000"; W=Z)},
			     {lex(L_id1,Clause)},
			     {lex(L_id2,Clause)},
			     {lex(L_id3,Clause)},
			     {lex(L_id4,Clause),
			     string_concat(L_id1,L_id2,X),
			     string_concat(X,L_id3,Y),
			     string_concat(Y,L_id4,W)}.


prefix_condition(Input,ipv6):- split_string(Input,'/',' ',[X1,X2]),
                               number_string(N,X2),
                               between(1,128,N),
                               colon_separated(X1,ipv6).

ipv6clause(Input):- prefix_condition(Input,ipv6);
                    colon_separated(Input,ipv6).

ipv6([TCP,[Type,Code],[IPv6address_Source,IPv6address_Dest]]):- tcp(TCP),
                                                                icmpv6(Type,Code),
                                                                ipv6clause(IPv6address_Source),
                                                                ipv6clause(IPv6address_Dest),
                                                                not(blocked_ipv6([TCP,_,[IPv6address_Source,IPv6address_Dest]])).

blocked_ipv6clause(Input,Clause) :- lex(Input,Clause).

blocked_ipv6([TCP,_,[IPv6address_Source,IPv6address_Dest]]) :- blocked_tcp(TCP);
                                                               blocked_ipv6clause(IPv6address_Source,ipv6_source);
                                                               blocked_ipv6clause(IPv6address_Dest,ipv6_dest).

% allow,reject and drop.

allow([Adapter,Ethernet,IPv4,IPv6],Status) :- adapter(Adapter),
                                              ethernet(Ethernet),
                                              ipv4(IPv4),
                                              ipv6(IPv6),
                                              Status="Allowed".

reject([_,Ethernet,IPv4,IPv6],Status) :- ( blocked_ethernet(Ethernet);
                                           blocked_ipv4(IPv4);
                                           blocked_ipv6(IPv6)),
                                           Status="Rejected".


drop(_,Status) :-  Status="Dropped".

% packet input

packet([Adapter,Ethernet,IPv4,IPv6],Status) :- consult('Database.pl'),
                                               ( allow([Adapter,Ethernet,IPv4,IPv6],Status),!);
                                               ( reject([_,Ethernet,IPv4,IPv6],Status),!);
                                               ( drop(_,Status)).
