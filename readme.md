# Firewalls Protocols using Prolog Programming

The project intends to implement the firewall protocols using prolog programming language and predicate logic. The project was done in partial fulfillment of my undergraduation at BITS Pilani.

The following content may be referred as an explanation for the code.

## Predicates:

1. **member(X,List)** checks whether X is a member of the List.
2. **check_list([X|List],Clause)** for every member X of the list it checks for different clauses by calling the predicate check.
3. **expression(Input,Clause)** checks whether input is a valid expression under the given clause; it's valid in four formats - "any" , <value> , <value1>,<value2> , <value1>-<value2>.
4. **literal(Input,Clause)** calls predicate check in case of single value i.e. <value1>
5. **comma_separated(Input,Clause)** calls predicate check_list after splitting the <value1>,<value2> into different values and adding them to the list.
6. **range_of_values(Input,Clause)** calls predicate check after splitting the <value1>-<value2> into two different values. It also ensures that <value1> is less than <value2>.
7. **check(X,Clause)** checks whether the lexicon holds for X under the given Clause.
8. **packet([Adapter,Ethernet,IPv4,IPv6],Status)** calls predicate allow OR reject OR drop.
9. **allow([Adapter,Ethernet,IPv4,IPv6],Status)** calls predicate Adapter, Ethernet, ipv4 and ipv6. If true, it assigns Status to Allowed.
10. **reject([_,Ethernet,IPv4,IPv6],Status)** calls predicate blocked_ethernet OR blocked_ipv4 OR blocked_ipv6. If true, it assigns Status to Rejected.
11. **drop(_,Status)** assigns Status to Dropped.



###	Adapter Clause:

1. **adapter(Input)** takes input from the user and passes the input in predicate expression.


###	Ethernet Clause:

1. **ethernet([Type,id])** takes a list as an argument and checks type and id for valid cases.
2. **blocked_ethernet([Type,id])** checks if ethernet protocol id is blocked or not.


###	TCP/UDP/ICMP:

1. **tcp(Input)** takes input from the user and passes the input in predicate expression.
2. **icmpv4(Type,Code)** passes the Type to predicate icmp_type and Code to predicate icmp_both_code. It finally tells if the Input is valid in icmpv4.
3. **icmpv6(Type,Code)** passes the Type to predicate icmp_v6_type and Code to predicate icmp_both_code. It finally tells if the Input is valid in icmpv6.
4. **icmp_type(Input)** takes Input as Type from predicate icmpv4 and calls predicate expression. 
5. **icmp_v6_type(Input)** takes Input as Type from predicate icmpv6 and calls predicate expression. 
6. **icmp_both_code(Input)** takes Input from icmpv4 and icmpv6 as Code and calls the predicate expression. 
7. **blocked_tcp(Input)** checks if the input satisfies the blocked condition of TCP.
8. **blocked_icmp(Input)** checks if the input satisfies the blocked condition of ICMP.


###	IPv4 Clause:

1. **netmask_condition(Input,IPaddress)** calls predicate  dot_separated after splitting the string using '/'.
2. **ipv4([TCP,[Type Code],[IPaddress_Source, IPaddress_Dest]])** calls predicate icmpv4 and ipclause for source and destination address.
3. **blocked_ipv4(Input)** calls predicate blocked_tcp and predicate blocked_ipclause.
4. **dot_separated(Input,Clause)** calls predicate check_list after splitting the Input and adding them to the list.
5. **ipclause(Input)** calls predicate dot_separated with Input and IPaddress.
6. **blocked_ipclause(Input, Clause)** checks for blocking condition of IPaddress.


###	IPv6 Clause:

1. **colon_separated(Input,Clause)** calls predicate check_list after splitting the Input and adding them to the list.
2. **sequence_of_four(Clause)** checks if the terms separated by colon are a 4 digit number or 0 or an empty string.
3. **prefix_condition(Input,ipv6)** calls predicate  colon_separated after splitting the string using '/'.
4. **ipv6clause(Input)** calls predicate colon_separated and predicate prefix_condition.
5. **ipv6([TCP,[Type Code],[IPv6address_Source, IPv6address_Dest]])** calls predicate icmpv6 and ipv6clause for source and destination address.
6. **blocked_ipv6(Input)** calls predicate blocked_tcp and predicate blocked_ipv6clause.
7. **blocked_ipv6clause(Input, Clause)** checks for blocking condition of IPv6address.
