# libinjection SQL-injection fingerprints resolved

[libinjection](https://github.com/libinjection/libinjection) is a SQLi detection library.
Strings are checked and transformed into fingerprints based on Operators, etc.
The result is that, for example ModSecurity doesn't display the SQL command, but only the fingerprint.
Sadly the libinjection developers provided only a list of fingerprints, but NOT a list of the strings they represent.
And some don't understand that only the fingerprnt is shown in the ModSecurity message and NOT the SQL command used in the attack

Generated with:
```
user@host:~/git/libinjection/src (main)$ ./fingerprints2sqli.py >> libinjection-sqli-fingerprints.md
```


```
&(1)U and ( 1 ) union
&(1)o and ( 1 ) *
&(1o( and ( 1 * (
&(1of and ( 1 * convert
&(1os and ( 1 * "1"
&(1ov and ( 1 * @version
&(f() and ( convert ( )
&(f(1 and ( convert ( 1
&(f(f and ( convert ( convert
&(f(n and ( convert ( aname
&(f(s and ( convert ( "1"
&(f(v and ( convert ( @version
&(n)U and ( aname ) union
&(n)o and ( aname ) *
&(no( and ( aname * (
&(nof and ( aname * convert
&(nos and ( aname * "1"
&(nov and ( aname * @version
&(s)U and ( "1" ) union
&(s)o and ( "1" ) *
&(so( and ( "1" * (
&(so1 and ( "1" * 1
&(sof and ( "1" * convert
&(son and ( "1" * aname
&(sos and ( "1" * "1"
&(sov and ( "1" * @version
&(v)U and ( @version ) union
&(v)o and ( @version ) *
&(vo( and ( @version * (
&(vof and ( @version * convert
&(vos and ( @version * "1"
&1UE( and 1 union select (
&1UE1 and 1 union select 1
&1UEf and 1 union select convert
&1UEk and 1 union select JOIN
&1UEn and 1 union select aname
&1UEs and 1 union select "1"
&1UEv and 1 union select @version
&1o(1 and 1 * ( 1
&1o(f and 1 * ( convert
&1o(n and 1 * ( aname
&1o(s and 1 * ( "1"
&1o(v and 1 * ( @version
&1of( and 1 * convert (
&1os( and 1 * "1" (
&1os1 and 1 * "1" 1
&1osU and 1 * "1" union
&1osf and 1 * "1" convert
&1osv and 1 * "1" @version
&1ov( and 1 * @version (
&1ovU and 1 * @version union
&1ovf and 1 * @version convert
&1ovo and 1 * @version *
&1ovs and 1 * @version "1"
&f()U and convert ( ) union
&f()o and convert ( ) *
&f(1) and convert ( 1 )
&f(1o and convert ( 1 *
&f(f( and convert ( convert (
&f(n) and convert ( aname )
&f(no and convert ( aname *
&f(s) and convert ( "1" )
&f(so and convert ( "1" *
&f(v) and convert ( @version )
&f(vo and convert ( @version *
&nUE( and aname union select (
&nUE1 and aname union select 1
&nUEf and aname union select convert
&nUEk and aname union select JOIN
&nUEn and aname union select aname
&nUEs and aname union select "1"
&nUEv and aname union select @version
&no(1 and aname * ( 1
&no(f and aname * ( convert
&no(n and aname * ( aname
&no(s and aname * ( "1"
&no(v and aname * ( @version
&nof( and aname * convert (
&nos( and aname * "1" (
&nos1 and aname * "1" 1
&nosU and aname * "1" union
&nosf and aname * "1" convert
&nosv and aname * "1" @version
&nov( and aname * @version (
&novU and aname * @version union
&novf and aname * @version convert
&novo and aname * @version *
&novs and aname * @version "1"
&sUE( and "1" union select (
&sUE1 and "1" union select 1
&sUEf and "1" union select convert
&sUEk and "1" union select JOIN
&sUEn and "1" union select aname
&sUEs and "1" union select "1"
&sUEv and "1" union select @version
&so(1 and "1" * ( 1
&so(f and "1" * ( convert
&so(n and "1" * ( aname
&so(s and "1" * ( "1"
&so(v and "1" * ( @version
&so1( and "1" * 1 (
&so1U and "1" * 1 union
&so1f and "1" * 1 convert
&so1n and "1" * 1 aname
&so1s and "1" * 1 "1"
&so1v and "1" * 1 @version
&sof( and "1" * convert (
&son( and "1" * aname (
&son1 and "1" * aname 1
&sonU and "1" * aname union
&sonf and "1" * aname convert
&sos( and "1" * "1" (
&sos1 and "1" * "1" 1
&sosU and "1" * "1" union
&sosf and "1" * "1" convert
&sosv and "1" * "1" @version
&sov( and "1" * @version (
&sovU and "1" * @version union
&sovf and "1" * @version convert
&sovo and "1" * @version *
&sovs and "1" * @version "1"
&vUE( and @version union select (
&vUE1 and @version union select 1
&vUEf and @version union select convert
&vUEk and @version union select JOIN
&vUEn and @version union select aname
&vUEs and @version union select "1"
&vUEv and @version union select @version
&vo(1 and @version * ( 1
&vo(f and @version * ( convert
&vo(n and @version * ( aname
&vo(s and @version * ( "1"
&vo(v and @version * ( @version
&vof( and @version * convert (
&vos( and @version * "1" (
&vos1 and @version * "1" 1
&vosU and @version * "1" union
&vosf and @version * "1" convert
&vosv and @version * "1" @version
)&(Ek ) and ( select JOIN
)&(En ) and ( select aname
)UE(1 ) union select ( 1
)UE(f ) union select ( convert
)UE(n ) union select ( aname
)UE(s ) union select ( "1"
)UE(v ) union select ( @version
)UE1k ) union select 1 JOIN
)UE1o ) union select 1 *
)UEf( ) union select convert (
)UEk( ) union select JOIN (
)UEk1 ) union select JOIN 1
)UEkf ) union select JOIN convert
)UEkn ) union select JOIN aname
)UEks ) union select JOIN "1"
)UEkv ) union select JOIN @version
)UEnk ) union select aname JOIN
)UEno ) union select aname *
)UEsk ) union select "1" JOIN
)UEso ) union select "1" *
)UEvk ) union select @version JOIN
)UEvo ) union select @version *
1&(1& 1 and ( 1 and
1&(1) 1 and ( 1 )
1&(1, 1 and ( 1 ,
1&(1o 1 and ( 1 *
1&(E( 1 and ( select (
1&(E1 1 and ( select 1
1&(Ef 1 and ( select convert
1&(Ek 1 and ( select JOIN
1&(En 1 and ( select aname
1&(Eo 1 and ( select *
1&(Es 1 and ( select "1"
1&(Ev 1 and ( select @version
1&(f( 1 and ( convert (
1&(n& 1 and ( aname and
1&(n) 1 and ( aname )
1&(n, 1 and ( aname ,
1&(no 1 and ( aname *
1&(s& 1 and ( "1" and
1&(s) 1 and ( "1" )
1&(s, 1 and ( "1" ,
1&(so 1 and ( "1" *
1&(v& 1 and ( @version and
1&(v) 1 and ( @version )
1&(v, 1 and ( @version ,
1&(vo 1 and ( @version *
1&1 1 and 1
1&1&( 1 and 1 and (
1&1&1 1 and 1 and 1
1&1&f 1 and 1 and convert
1&1&n 1 and 1 and aname
1&1&s 1 and 1 and "1"
1&1&v 1 and 1 and @version
1&1)& 1 and 1 ) and
1&1)U 1 and 1 ) union
1&1)c 1 and 1 )  -- comment
1&1)o 1 and 1 ) *
1&1; 1 and 1 ;
1&1;E 1 and 1 ; select
1&1;T 1 and 1 ; DROP
1&1;c 1 and 1 ;  -- comment
1&1B( 1 and 1 group by (
1&1B1 1 and 1 group by 1
1&1Bf 1 and 1 group by convert
1&1Bn 1 and 1 group by aname
1&1Bs 1 and 1 group by "1"
1&1Bv 1 and 1 group by @version
1&1Ek 1 and 1 select JOIN
1&1En 1 and 1 select aname
1&1Tn 1 and 1 DROP aname
1&1U 1 and 1 union
1&1U( 1 and 1 union (
1&1U; 1 and 1 union ;
1&1UE 1 and 1 union select
1&1Uc 1 and 1 union  -- comment
1&1c 1 and 1  -- comment
1&1f( 1 and 1 convert (
1&1k( 1 and 1 JOIN (
1&1k1 1 and 1 JOIN 1
1&1kf 1 and 1 JOIN convert
1&1kn 1 and 1 JOIN aname
1&1ks 1 and 1 JOIN "1"
1&1kv 1 and 1 JOIN @version
1&1o( 1 and 1 * (
1&1of 1 and 1 * convert
1&1os 1 and 1 * "1"
1&1ov 1 and 1 * @version
1&E(1 1 and select ( 1
1&E(f 1 and select ( convert
1&E(n 1 and select ( aname
1&E(o 1 and select ( *
1&E(s 1 and select ( "1"
1&E(v 1 and select ( @version
1&E1 1 and select 1
1&E1; 1 and select 1 ;
1&E1c 1 and select 1  -- comment
1&E1k 1 and select 1 JOIN
1&E1o 1 and select 1 *
1&EUE 1 and select union select
1&Ef( 1 and select convert (
1&Ek( 1 and select JOIN (
1&Ek1 1 and select JOIN 1
1&EkU 1 and select JOIN union
1&Ekf 1 and select JOIN convert
1&Ekn 1 and select JOIN aname
1&Eks 1 and select JOIN "1"
1&Ekv 1 and select JOIN @version
1&En 1 and select aname
1&En; 1 and select aname ;
1&Enc 1 and select aname  -- comment
1&Enk 1 and select aname JOIN
1&Eno 1 and select aname *
1&Es 1 and select "1"
1&Es; 1 and select "1" ;
1&Esc 1 and select "1"  -- comment
1&Esk 1 and select "1" JOIN
1&Eso 1 and select "1" *
1&Ev 1 and select @version
1&Ev; 1 and select @version ;
1&Evc 1 and select @version  -- comment
1&Evk 1 and select @version JOIN
1&Evo 1 and select @version *
1&f() 1 and convert ( )
1&f(1 1 and convert ( 1
1&f(E 1 and convert ( select
1&f(f 1 and convert ( convert
1&f(n 1 and convert ( aname
1&f(s 1 and convert ( "1"
1&f(v 1 and convert ( @version
1&k&( 1 and JOIN and (
1&k&1 1 and JOIN and 1
1&k&f 1 and JOIN and convert
1&k&n 1 and JOIN and aname
1&k&s 1 and JOIN and "1"
1&k&v 1 and JOIN and @version
1&k(1 1 and JOIN ( 1
1&k(f 1 and JOIN ( convert
1&k(n 1 and JOIN ( aname
1&k(s 1 and JOIN ( "1"
1&k(v 1 and JOIN ( @version
1&k1o 1 and JOIN 1 *
1&kc 1 and JOIN  -- comment
1&kf( 1 and JOIN convert (
1&knk 1 and JOIN aname JOIN
1&ko( 1 and JOIN * (
1&ko1 1 and JOIN * 1
1&kof 1 and JOIN * convert
1&kok 1 and JOIN * JOIN
1&kon 1 and JOIN * aname
1&kos 1 and JOIN * "1"
1&kov 1 and JOIN * @version
1&kso 1 and JOIN "1" *
1&kvo 1 and JOIN @version *
1&n&( 1 and aname and (
1&n&1 1 and aname and 1
1&n&f 1 and aname and convert
1&n&n 1 and aname and aname
1&n&s 1 and aname and "1"
1&n&v 1 and aname and @version
1&n)& 1 and aname ) and
1&n)U 1 and aname ) union
1&n)c 1 and aname )  -- comment
1&n)o 1 and aname ) *
1&n; 1 and aname ;
1&n;E 1 and aname ; select
1&n;T 1 and aname ; DROP
1&n;c 1 and aname ;  -- comment
1&nB( 1 and aname group by (
1&nB1 1 and aname group by 1
1&nBf 1 and aname group by convert
1&nBn 1 and aname group by aname
1&nBs 1 and aname group by "1"
1&nBv 1 and aname group by @version
1&nEn 1 and aname select aname
1&nTn 1 and aname DROP aname
1&nU 1 and aname union
1&nU( 1 and aname union (
1&nU; 1 and aname union ;
1&nUE 1 and aname union select
1&nUc 1 and aname union  -- comment
1&nc 1 and aname  -- comment
1&nf( 1 and aname convert (
1&nk( 1 and aname JOIN (
1&nk1 1 and aname JOIN 1
1&nkf 1 and aname JOIN convert
1&nkn 1 and aname JOIN aname
1&nks 1 and aname JOIN "1"
1&nkv 1 and aname JOIN @version
1&no( 1 and aname * (
1&nof 1 and aname * convert
1&nos 1 and aname * "1"
1&nov 1 and aname * @version
1&s 1 and "1"
1&s&( 1 and "1" and (
1&s&1 1 and "1" and 1
1&s&f 1 and "1" and convert
1&s&n 1 and "1" and aname
1&s&s 1 and "1" and "1"
1&s&v 1 and "1" and @version
1&s)& 1 and "1" ) and
1&s)U 1 and "1" ) union
1&s)c 1 and "1" )  -- comment
1&s)o 1 and "1" ) *
1&s1 1 and "1" 1
1&s1; 1 and "1" 1 ;
1&s1c 1 and "1" 1  -- comment
1&s; 1 and "1" ;
1&s;E 1 and "1" ; select
1&s;T 1 and "1" ; DROP
1&s;c 1 and "1" ;  -- comment
1&sB( 1 and "1" group by (
1&sB1 1 and "1" group by 1
1&sBf 1 and "1" group by convert
1&sBn 1 and "1" group by aname
1&sBs 1 and "1" group by "1"
1&sBv 1 and "1" group by @version
1&sEk 1 and "1" select JOIN
1&sEn 1 and "1" select aname
1&sTn 1 and "1" DROP aname
1&sU 1 and "1" union
1&sU( 1 and "1" union (
1&sU; 1 and "1" union ;
1&sUE 1 and "1" union select
1&sUc 1 and "1" union  -- comment
1&sc 1 and "1"  -- comment
1&sf( 1 and "1" convert (
1&sk( 1 and "1" JOIN (
1&sk1 1 and "1" JOIN 1
1&skf 1 and "1" JOIN convert
1&skn 1 and "1" JOIN aname
1&sks 1 and "1" JOIN "1"
1&skv 1 and "1" JOIN @version
1&so( 1 and "1" * (
1&so1 1 and "1" * 1
1&sof 1 and "1" * convert
1&son 1 and "1" * aname
1&sos 1 and "1" * "1"
1&sov 1 and "1" * @version
1&sv 1 and "1" @version
1&sv; 1 and "1" @version ;
1&svc 1 and "1" @version  -- comment
1&svo 1 and "1" @version *
1&v 1 and @version
1&v&( 1 and @version and (
1&v&1 1 and @version and 1
1&v&f 1 and @version and convert
1&v&n 1 and @version and aname
1&v&s 1 and @version and "1"
1&v&v 1 and @version and @version
1&v)& 1 and @version ) and
1&v)U 1 and @version ) union
1&v)c 1 and @version )  -- comment
1&v)o 1 and @version ) *
1&v; 1 and @version ;
1&v;E 1 and @version ; select
1&v;T 1 and @version ; DROP
1&v;c 1 and @version ;  -- comment
1&vB( 1 and @version group by (
1&vB1 1 and @version group by 1
1&vBf 1 and @version group by convert
1&vBn 1 and @version group by aname
1&vBs 1 and @version group by "1"
1&vBv 1 and @version group by @version
1&vEk 1 and @version select JOIN
1&vEn 1 and @version select aname
1&vTn 1 and @version DROP aname
1&vU 1 and @version union
1&vU( 1 and @version union (
1&vU; 1 and @version union ;
1&vUE 1 and @version union select
1&vUc 1 and @version union  -- comment
1&vc 1 and @version  -- comment
1&vf( 1 and @version convert (
1&vk( 1 and @version JOIN (
1&vk1 1 and @version JOIN 1
1&vkf 1 and @version JOIN convert
1&vkn 1 and @version JOIN aname
1&vks 1 and @version JOIN "1"
1&vkv 1 and @version JOIN @version
1&vo( 1 and @version * (
1&vof 1 and @version * convert
1&vos 1 and @version * "1"
1&vs 1 and @version "1"
1&vs; 1 and @version "1" ;
1&vsc 1 and @version "1"  -- comment
1&vso 1 and @version "1" *
1(Ef( 1 ( select convert (
1(Ekf 1 ( select JOIN convert
1(Ekn 1 ( select JOIN aname
1(Enk 1 ( select aname JOIN
1(U(E 1 ( union ( select
1)&(1 1 ) and ( 1
1)&(E 1 ) and ( select
1)&(f 1 ) and ( convert
1)&(n 1 ) and ( aname
1)&(s 1 ) and ( "1"
1)&(v 1 ) and ( @version
1)&1 1 ) and 1
1)&1& 1 ) and 1 and
1)&1) 1 ) and 1 )
1)&1; 1 ) and 1 ;
1)&1B 1 ) and 1 group by
1)&1U 1 ) and 1 union
1)&1c 1 ) and 1  -- comment
1)&1f 1 ) and 1 convert
1)&1o 1 ) and 1 *
1)&f( 1 ) and convert (
1)&n 1 ) and aname
1)&n& 1 ) and aname and
1)&n) 1 ) and aname )
1)&n; 1 ) and aname ;
1)&nB 1 ) and aname group by
1)&nU 1 ) and aname union
1)&nc 1 ) and aname  -- comment
1)&nf 1 ) and aname convert
1)&no 1 ) and aname *
1)&s 1 ) and "1"
1)&s& 1 ) and "1" and
1)&s) 1 ) and "1" )
1)&s; 1 ) and "1" ;
1)&sB 1 ) and "1" group by
1)&sU 1 ) and "1" union
1)&sc 1 ) and "1"  -- comment
1)&sf 1 ) and "1" convert
1)&so 1 ) and "1" *
1)&v 1 ) and @version
1)&v& 1 ) and @version and
1)&v) 1 ) and @version )
1)&v; 1 ) and @version ;
1)&vB 1 ) and @version group by
1)&vU 1 ) and @version union
1)&vc 1 ) and @version  -- comment
1)&vf 1 ) and @version convert
1)&vo 1 ) and @version *
1),(1 1 ) , ( 1
1),(f 1 ) , ( convert
1),(n 1 ) , ( aname
1),(s 1 ) , ( "1"
1),(v 1 ) , ( @version
1);E( 1 ) ; select (
1);E1 1 ) ; select 1
1);Ef 1 ) ; select convert
1);Ek 1 ) ; select JOIN
1);En 1 ) ; select aname
1);Eo 1 ) ; select *
1);Es 1 ) ; select "1"
1);Ev 1 ) ; select @version
1);T( 1 ) ; DROP (
1);T1 1 ) ; DROP 1
1);Tf 1 ) ; DROP convert
1);Tk 1 ) ; DROP JOIN
1);Tn 1 ) ; DROP aname
1);To 1 ) ; DROP *
1);Ts 1 ) ; DROP "1"
1);Tv 1 ) ; DROP @version
1)B(1 1 ) group by ( 1
1)B(f 1 ) group by ( convert
1)B(n 1 ) group by ( aname
1)B(s 1 ) group by ( "1"
1)B(v 1 ) group by ( @version
1)B1 1 ) group by 1
1)B1& 1 ) group by 1 and
1)B1; 1 ) group by 1 ;
1)B1U 1 ) group by 1 union
1)B1c 1 ) group by 1  -- comment
1)B1k 1 ) group by 1 JOIN
1)B1n 1 ) group by 1 aname
1)B1o 1 ) group by 1 *
1)Bf( 1 ) group by convert (
1)Bn 1 ) group by aname
1)Bn& 1 ) group by aname and
1)Bn; 1 ) group by aname ;
1)BnU 1 ) group by aname union
1)Bnc 1 ) group by aname  -- comment
1)Bnk 1 ) group by aname JOIN
1)Bno 1 ) group by aname *
1)Bs 1 ) group by "1"
1)Bs& 1 ) group by "1" and
1)Bs; 1 ) group by "1" ;
1)BsU 1 ) group by "1" union
1)Bsc 1 ) group by "1"  -- comment
1)Bsk 1 ) group by "1" JOIN
1)Bso 1 ) group by "1" *
1)Bv 1 ) group by @version
1)Bv& 1 ) group by @version and
1)Bv; 1 ) group by @version ;
1)BvU 1 ) group by @version union
1)Bvc 1 ) group by @version  -- comment
1)Bvk 1 ) group by @version JOIN
1)Bvo 1 ) group by @version *
1)E(1 1 ) select ( 1
1)E(f 1 ) select ( convert
1)E(n 1 ) select ( aname
1)E(s 1 ) select ( "1"
1)E(v 1 ) select ( @version
1)E1c 1 ) select 1  -- comment
1)E1o 1 ) select 1 *
1)Ef( 1 ) select convert (
1)Ek( 1 ) select JOIN (
1)Ek1 1 ) select JOIN 1
1)Ekf 1 ) select JOIN convert
1)Ekn 1 ) select JOIN aname
1)Eks 1 ) select JOIN "1"
1)Ekv 1 ) select JOIN @version
1)Enc 1 ) select aname  -- comment
1)Eno 1 ) select aname *
1)Esc 1 ) select "1"  -- comment
1)Eso 1 ) select "1" *
1)Evc 1 ) select @version  -- comment
1)Evo 1 ) select @version *
1)U(E 1 ) union ( select
1)UE( 1 ) union select (
1)UE1 1 ) union select 1
1)UEf 1 ) union select convert
1)UEk 1 ) union select JOIN
1)UEn 1 ) union select aname
1)UEs 1 ) union select "1"
1)UEv 1 ) union select @version
1)c 1 )  -- comment
1)f(f 1 ) convert ( convert
1)k(1 1 ) JOIN ( 1
1)k(f 1 ) JOIN ( convert
1)k(n 1 ) JOIN ( aname
1)k(s 1 ) JOIN ( "1"
1)k(v 1 ) JOIN ( @version
1)k1& 1 ) JOIN 1 and
1)k1; 1 ) JOIN 1 ;
1)k1B 1 ) JOIN 1 group by
1)k1E 1 ) JOIN 1 select
1)k1U 1 ) JOIN 1 union
1)k1o 1 ) JOIN 1 *
1)kB( 1 ) JOIN group by (
1)kB1 1 ) JOIN group by 1
1)kBf 1 ) JOIN group by convert
1)kBn 1 ) JOIN group by aname
1)kBs 1 ) JOIN group by "1"
1)kBv 1 ) JOIN group by @version
1)kUE 1 ) JOIN union select
1)kf( 1 ) JOIN convert (
1)kn& 1 ) JOIN aname and
1)kn; 1 ) JOIN aname ;
1)knB 1 ) JOIN aname group by
1)knE 1 ) JOIN aname select
1)knU 1 ) JOIN aname union
1)knc 1 ) JOIN aname  -- comment
1)knk 1 ) JOIN aname JOIN
1)ks& 1 ) JOIN "1" and
1)ks; 1 ) JOIN "1" ;
1)ksB 1 ) JOIN "1" group by
1)ksE 1 ) JOIN "1" select
1)ksU 1 ) JOIN "1" union
1)kso 1 ) JOIN "1" *
1)kv& 1 ) JOIN @version and
1)kv; 1 ) JOIN @version ;
1)kvB 1 ) JOIN @version group by
1)kvE 1 ) JOIN @version select
1)kvU 1 ) JOIN @version union
1)kvo 1 ) JOIN @version *
1)o(1 1 ) * ( 1
1)o(E 1 ) * ( select
1)o(f 1 ) * ( convert
1)o(n 1 ) * ( aname
1)o(s 1 ) * ( "1"
1)o(v 1 ) * ( @version
1)o1 1 ) * 1
1)o1& 1 ) * 1 and
1)o1) 1 ) * 1 )
1)o1; 1 ) * 1 ;
1)o1B 1 ) * 1 group by
1)o1U 1 ) * 1 union
1)o1c 1 ) * 1  -- comment
1)o1k 1 ) * 1 JOIN
1)of( 1 ) * convert (
1)on& 1 ) * aname and
1)on) 1 ) * aname )
1)on; 1 ) * aname ;
1)onB 1 ) * aname group by
1)onU 1 ) * aname union
1)onc 1 ) * aname  -- comment
1)onk 1 ) * aname JOIN
1)os 1 ) * "1"
1)os& 1 ) * "1" and
1)os) 1 ) * "1" )
1)os; 1 ) * "1" ;
1)osB 1 ) * "1" group by
1)osU 1 ) * "1" union
1)osc 1 ) * "1"  -- comment
1)osk 1 ) * "1" JOIN
1)ov 1 ) * @version
1)ov& 1 ) * @version and
1)ov) 1 ) * @version )
1)ov; 1 ) * @version ;
1)ovB 1 ) * @version group by
1)ovU 1 ) * @version union
1)ovc 1 ) * @version  -- comment
1)ovk 1 ) * @version JOIN
1)ovo 1 ) * @version *
1,(1) 1 , ( 1 )
1,(1o 1 , ( 1 *
1,(E( 1 , ( select (
1,(E1 1 , ( select 1
1,(Ef 1 , ( select convert
1,(Ek 1 , ( select JOIN
1,(En 1 , ( select aname
1,(Es 1 , ( select "1"
1,(Ev 1 , ( select @version
1,(f( 1 , ( convert (
1,(n) 1 , ( aname )
1,(no 1 , ( aname *
1,(s) 1 , ( "1" )
1,(so 1 , ( "1" *
1,(v) 1 , ( @version )
1,(vo 1 , ( @version *
1,f() 1 , convert ( )
1,f(1 1 , convert ( 1
1,f(f 1 , convert ( convert
1,f(n 1 , convert ( aname
1,f(s 1 , convert ( "1"
1,f(v 1 , convert ( @version
1;E(1 1 ; select ( 1
1;E(E 1 ; select ( select
1;E(f 1 ; select ( convert
1;E(n 1 ; select ( aname
1;E(s 1 ; select ( "1"
1;E(v 1 ; select ( @version
1;E1, 1 ; select 1 ,
1;E1; 1 ; select 1 ;
1;E1T 1 ; select 1 DROP
1;E1c 1 ; select 1  -- comment
1;E1k 1 ; select 1 JOIN
1;E1o 1 ; select 1 *
1;Ef( 1 ; select convert (
1;Ek( 1 ; select JOIN (
1;Ek1 1 ; select JOIN 1
1;Ekf 1 ; select JOIN convert
1;Ekn 1 ; select JOIN aname
1;Eko 1 ; select JOIN *
1;Eks 1 ; select JOIN "1"
1;Ekv 1 ; select JOIN @version
1;En, 1 ; select aname ,
1;En; 1 ; select aname ;
1;EnE 1 ; select aname select
1;EnT 1 ; select aname DROP
1;Enc 1 ; select aname  -- comment
1;Enk 1 ; select aname JOIN
1;Eno 1 ; select aname *
1;Es, 1 ; select "1" ,
1;Es; 1 ; select "1" ;
1;EsT 1 ; select "1" DROP
1;Esc 1 ; select "1"  -- comment
1;Esk 1 ; select "1" JOIN
1;Eso 1 ; select "1" *
1;Ev, 1 ; select @version ,
1;Ev; 1 ; select @version ;
1;EvT 1 ; select @version DROP
1;Evc 1 ; select @version  -- comment
1;Evk 1 ; select @version JOIN
1;Evo 1 ; select @version *
1;T(1 1 ; DROP ( 1
1;T(E 1 ; DROP ( select
1;T(c 1 ; DROP (  -- comment
1;T(f 1 ; DROP ( convert
1;T(n 1 ; DROP ( aname
1;T(s 1 ; DROP ( "1"
1;T(v 1 ; DROP ( @version
1;T1( 1 ; DROP 1 (
1;T1, 1 ; DROP 1 ,
1;T1; 1 ; DROP 1 ;
1;T1T 1 ; DROP 1 DROP
1;T1c 1 ; DROP 1  -- comment
1;T1f 1 ; DROP 1 convert
1;T1k 1 ; DROP 1 JOIN
1;T1o 1 ; DROP 1 *
1;T; 1 ; DROP ;
1;T;c 1 ; DROP ;  -- comment
1;TTn 1 ; DROP DROP aname
1;Tf( 1 ; DROP convert (
1;Tk( 1 ; DROP JOIN (
1;Tk1 1 ; DROP JOIN 1
1;Tkf 1 ; DROP JOIN convert
1;Tkk 1 ; DROP JOIN JOIN
1;Tkn 1 ; DROP JOIN aname
1;Tko 1 ; DROP JOIN *
1;Tks 1 ; DROP JOIN "1"
1;Tkv 1 ; DROP JOIN @version
1;Tn( 1 ; DROP aname (
1;Tn, 1 ; DROP aname ,
1;Tn1 1 ; DROP aname 1
1;Tn; 1 ; DROP aname ;
1;TnT 1 ; DROP aname DROP
1;Tnc 1 ; DROP aname  -- comment
1;Tnf 1 ; DROP aname convert
1;Tnk 1 ; DROP aname JOIN
1;Tnn 1 ; DROP aname aname
1;Tno 1 ; DROP aname *
1;Tns 1 ; DROP aname "1"
1;Tnv 1 ; DROP aname @version
1;To( 1 ; DROP * (
1;Ts( 1 ; DROP "1" (
1;Ts, 1 ; DROP "1" ,
1;Ts; 1 ; DROP "1" ;
1;TsT 1 ; DROP "1" DROP
1;Tsc 1 ; DROP "1"  -- comment
1;Tsf 1 ; DROP "1" convert
1;Tsk 1 ; DROP "1" JOIN
1;Tso 1 ; DROP "1" *
1;Tv( 1 ; DROP @version (
1;Tv, 1 ; DROP @version ,
1;Tv; 1 ; DROP @version ;
1;TvT 1 ; DROP @version DROP
1;Tvc 1 ; DROP @version  -- comment
1;Tvf 1 ; DROP @version convert
1;Tvk 1 ; DROP @version JOIN
1;Tvo 1 ; DROP @version *
1;n:T 1 ; aname : DROP
1A(f( 1 COLLATE ( convert (
1A(n) 1 COLLATE ( aname )
1A(no 1 COLLATE ( aname *
1A(s) 1 COLLATE ( "1" )
1A(so 1 COLLATE ( "1" *
1A(v) 1 COLLATE ( @version )
1A(vo 1 COLLATE ( @version *
1Af() 1 COLLATE convert ( )
1Af(1 1 COLLATE convert ( 1
1Af(f 1 COLLATE convert ( convert
1Af(n 1 COLLATE convert ( aname
1Af(s 1 COLLATE convert ( "1"
1Af(v 1 COLLATE convert ( @version
1AsUE 1 COLLATE "1" union select
1Aso( 1 COLLATE "1" * (
1Aso1 1 COLLATE "1" * 1
1Asof 1 COLLATE "1" * convert
1Ason 1 COLLATE "1" * aname
1Asos 1 COLLATE "1" * "1"
1Asov 1 COLLATE "1" * @version
1AtUE 1 COLLATE binary union select
1Ato( 1 COLLATE binary * (
1Ato1 1 COLLATE binary * 1
1Atof 1 COLLATE binary * convert
1Aton 1 COLLATE binary * aname
1Atos 1 COLLATE binary * "1"
1Atov 1 COLLATE binary * @version
1AvUE 1 COLLATE @version union select
1Avo( 1 COLLATE @version * (
1Avof 1 COLLATE @version * convert
1Avos 1 COLLATE @version * "1"
1B(1) 1 group by ( 1 )
1B(1o 1 group by ( 1 *
1B(f( 1 group by ( convert (
1B(no 1 group by ( aname *
1B(s) 1 group by ( "1" )
1B(so 1 group by ( "1" *
1B(v) 1 group by ( @version )
1B(vo 1 group by ( @version *
1B1 1 group by 1
1B1&( 1 group by 1 and (
1B1&1 1 group by 1 and 1
1B1&f 1 group by 1 and convert
1B1&n 1 group by 1 and aname
1B1&s 1 group by 1 and "1"
1B1&v 1 group by 1 and @version
1B1,( 1 group by 1 , (
1B1,f 1 group by 1 , convert
1B1; 1 group by 1 ;
1B1;c 1 group by 1 ;  -- comment
1B1B( 1 group by 1 group by (
1B1B1 1 group by 1 group by 1
1B1Bf 1 group by 1 group by convert
1B1Bn 1 group by 1 group by aname
1B1Bs 1 group by 1 group by "1"
1B1Bv 1 group by 1 group by @version
1B1U( 1 group by 1 union (
1B1UE 1 group by 1 union select
1B1c 1 group by 1  -- comment
1B1k( 1 group by 1 JOIN (
1B1k1 1 group by 1 JOIN 1
1B1kf 1 group by 1 JOIN convert
1B1kn 1 group by 1 JOIN aname
1B1ks 1 group by 1 JOIN "1"
1B1kv 1 group by 1 JOIN @version
1B1o( 1 group by 1 * (
1B1of 1 group by 1 * convert
1B1os 1 group by 1 * "1"
1B1ov 1 group by 1 * @version
1BE(1 1 group by select ( 1
1BE(f 1 group by select ( convert
1BE(n 1 group by select ( aname
1BE(s 1 group by select ( "1"
1BE(v 1 group by select ( @version
1BEk( 1 group by select JOIN (
1Bf() 1 group by convert ( )
1Bf(1 1 group by convert ( 1
1Bf(f 1 group by convert ( convert
1Bf(n 1 group by convert ( aname
1Bf(s 1 group by convert ( "1"
1Bf(v 1 group by convert ( @version
1Bn 1 group by aname
1Bn&( 1 group by aname and (
1Bn&1 1 group by aname and 1
1Bn&f 1 group by aname and convert
1Bn&n 1 group by aname and aname
1Bn&s 1 group by aname and "1"
1Bn&v 1 group by aname and @version
1Bn,( 1 group by aname , (
1Bn,f 1 group by aname , convert
1Bn; 1 group by aname ;
1Bn;c 1 group by aname ;  -- comment
1BnB( 1 group by aname group by (
1BnB1 1 group by aname group by 1
1BnBf 1 group by aname group by convert
1BnBn 1 group by aname group by aname
1BnBs 1 group by aname group by "1"
1BnBv 1 group by aname group by @version
1BnU( 1 group by aname union (
1BnUE 1 group by aname union select
1Bnc 1 group by aname  -- comment
1Bnk( 1 group by aname JOIN (
1Bnk1 1 group by aname JOIN 1
1Bnkf 1 group by aname JOIN convert
1Bnkn 1 group by aname JOIN aname
1Bnks 1 group by aname JOIN "1"
1Bnkv 1 group by aname JOIN @version
1Bno( 1 group by aname * (
1Bnof 1 group by aname * convert
1Bnos 1 group by aname * "1"
1Bnov 1 group by aname * @version
1Bs 1 group by "1"
1Bs&( 1 group by "1" and (
1Bs&1 1 group by "1" and 1
1Bs&f 1 group by "1" and convert
1Bs&n 1 group by "1" and aname
1Bs&s 1 group by "1" and "1"
1Bs&v 1 group by "1" and @version
1Bs,( 1 group by "1" , (
1Bs,f 1 group by "1" , convert
1Bs; 1 group by "1" ;
1Bs;c 1 group by "1" ;  -- comment
1BsB( 1 group by "1" group by (
1BsB1 1 group by "1" group by 1
1BsBf 1 group by "1" group by convert
1BsBn 1 group by "1" group by aname
1BsBs 1 group by "1" group by "1"
1BsBv 1 group by "1" group by @version
1BsU( 1 group by "1" union (
1BsUE 1 group by "1" union select
1Bsc 1 group by "1"  -- comment
1Bsk( 1 group by "1" JOIN (
1Bsk1 1 group by "1" JOIN 1
1Bskf 1 group by "1" JOIN convert
1Bskn 1 group by "1" JOIN aname
1Bsks 1 group by "1" JOIN "1"
1Bskv 1 group by "1" JOIN @version
1Bso( 1 group by "1" * (
1Bso1 1 group by "1" * 1
1Bsof 1 group by "1" * convert
1Bson 1 group by "1" * aname
1Bsos 1 group by "1" * "1"
1Bsov 1 group by "1" * @version
1Bv 1 group by @version
1Bv&( 1 group by @version and (
1Bv&1 1 group by @version and 1
1Bv&f 1 group by @version and convert
1Bv&n 1 group by @version and aname
1Bv&s 1 group by @version and "1"
1Bv&v 1 group by @version and @version
1Bv,( 1 group by @version , (
1Bv,f 1 group by @version , convert
1Bv; 1 group by @version ;
1Bv;c 1 group by @version ;  -- comment
1BvB( 1 group by @version group by (
1BvB1 1 group by @version group by 1
1BvBf 1 group by @version group by convert
1BvBn 1 group by @version group by aname
1BvBs 1 group by @version group by "1"
1BvBv 1 group by @version group by @version
1BvU( 1 group by @version union (
1BvUE 1 group by @version union select
1Bvc 1 group by @version  -- comment
1Bvk( 1 group by @version JOIN (
1Bvk1 1 group by @version JOIN 1
1Bvkf 1 group by @version JOIN convert
1Bvkn 1 group by @version JOIN aname
1Bvks 1 group by @version JOIN "1"
1Bvkv 1 group by @version JOIN @version
1Bvo( 1 group by @version * (
1Bvof 1 group by @version * convert
1Bvos 1 group by @version * "1"
1E(1) 1 select ( 1 )
1E(1o 1 select ( 1 *
1E(f( 1 select ( convert (
1E(n) 1 select ( aname )
1E(no 1 select ( aname *
1E(s) 1 select ( "1" )
1E(so 1 select ( "1" *
1E(v) 1 select ( @version )
1E(vo 1 select ( @version *
1E1;T 1 select 1 ; DROP
1E1T( 1 select 1 DROP (
1E1T1 1 select 1 DROP 1
1E1Tf 1 select 1 DROP convert
1E1Tn 1 select 1 DROP aname
1E1Ts 1 select 1 DROP "1"
1E1Tv 1 select 1 DROP @version
1E1UE 1 select 1 union select
1E1c 1 select 1  -- comment
1E1o( 1 select 1 * (
1E1of 1 select 1 * convert
1E1os 1 select 1 * "1"
1E1ov 1 select 1 * @version
1EU(1 1 select union ( 1
1EU(f 1 select union ( convert
1EU(n 1 select union ( aname
1EU(s 1 select union ( "1"
1EU(v 1 select union ( @version
1EU1, 1 select union 1 ,
1EU1c 1 select union 1  -- comment
1EU1o 1 select union 1 *
1EUEf 1 select union select convert
1EUEk 1 select union select JOIN
1EUf( 1 select union convert (
1EUs, 1 select union "1" ,
1EUsc 1 select union "1"  -- comment
1EUso 1 select union "1" *
1EUv, 1 select union @version ,
1EUvc 1 select union @version  -- comment
1EUvo 1 select union @version *
1Ef() 1 select convert ( )
1Ef(1 1 select convert ( 1
1Ef(f 1 select convert ( convert
1Ef(n 1 select convert ( aname
1Ef(s 1 select convert ( "1"
1Ef(v 1 select convert ( @version
1Ek(1 1 select JOIN ( 1
1Ek(E 1 select JOIN ( select
1Ek(f 1 select JOIN ( convert
1Ek(n 1 select JOIN ( aname
1Ek(s 1 select JOIN ( "1"
1Ek(v 1 select JOIN ( @version
1Ek1; 1 select JOIN 1 ;
1Ek1T 1 select JOIN 1 DROP
1Ek1U 1 select JOIN 1 union
1Ek1c 1 select JOIN 1  -- comment
1Ek1o 1 select JOIN 1 *
1EkU( 1 select JOIN union (
1EkU1 1 select JOIN union 1
1EkUE 1 select JOIN union select
1EkUf 1 select JOIN union convert
1EkUs 1 select JOIN union "1"
1EkUv 1 select JOIN union @version
1Ekf( 1 select JOIN convert (
1Ekn; 1 select JOIN aname ;
1EknE 1 select JOIN aname select
1EknT 1 select JOIN aname DROP
1EknU 1 select JOIN aname union
1Eknc 1 select JOIN aname  -- comment
1Ekok 1 select JOIN * JOIN
1Eks; 1 select JOIN "1" ;
1EksT 1 select JOIN "1" DROP
1EksU 1 select JOIN "1" union
1Eksc 1 select JOIN "1"  -- comment
1Ekso 1 select JOIN "1" *
1Ekv; 1 select JOIN @version ;
1EkvT 1 select JOIN @version DROP
1EkvU 1 select JOIN @version union
1Ekvc 1 select JOIN @version  -- comment
1Ekvo 1 select JOIN @version *
1En;T 1 select aname ; DROP
1EnEn 1 select aname select aname
1EnT( 1 select aname DROP (
1EnT1 1 select aname DROP 1
1EnTf 1 select aname DROP convert
1EnTn 1 select aname DROP aname
1EnTs 1 select aname DROP "1"
1EnTv 1 select aname DROP @version
1EnUE 1 select aname union select
1Enc 1 select aname  -- comment
1Eno( 1 select aname * (
1Enof 1 select aname * convert
1Enos 1 select aname * "1"
1Enov 1 select aname * @version
1Eokn 1 select * JOIN aname
1Es;T 1 select "1" ; DROP
1EsT( 1 select "1" DROP (
1EsT1 1 select "1" DROP 1
1EsTf 1 select "1" DROP convert
1EsTn 1 select "1" DROP aname
1EsTs 1 select "1" DROP "1"
1EsTv 1 select "1" DROP @version
1EsUE 1 select "1" union select
1Esc 1 select "1"  -- comment
1Eso( 1 select "1" * (
1Eso1 1 select "1" * 1
1Esof 1 select "1" * convert
1Eson 1 select "1" * aname
1Esos 1 select "1" * "1"
1Esov 1 select "1" * @version
1Ev;T 1 select @version ; DROP
1EvT( 1 select @version DROP (
1EvT1 1 select @version DROP 1
1EvTf 1 select @version DROP convert
1EvTn 1 select @version DROP aname
1EvTs 1 select @version DROP "1"
1EvTv 1 select @version DROP @version
1EvUE 1 select @version union select
1Evc 1 select @version  -- comment
1Evo( 1 select @version * (
1Evof 1 select @version * convert
1Evos 1 select @version * "1"
1T(1) 1 DROP ( 1 )
1T(1o 1 DROP ( 1 *
1T(f( 1 DROP ( convert (
1T(n) 1 DROP ( aname )
1T(no 1 DROP ( aname *
1T(s) 1 DROP ( "1" )
1T(so 1 DROP ( "1" *
1T(v) 1 DROP ( @version )
1T(vo 1 DROP ( @version *
1T1(f 1 DROP 1 ( convert
1T1o( 1 DROP 1 * (
1T1of 1 DROP 1 * convert
1T1os 1 DROP 1 * "1"
1T1ov 1 DROP 1 * @version
1TE(1 1 DROP select ( 1
1TE(f 1 DROP select ( convert
1TE(n 1 DROP select ( aname
1TE(s 1 DROP select ( "1"
1TE(v 1 DROP select ( @version
1TE1n 1 DROP select 1 aname
1TE1o 1 DROP select 1 *
1TEf( 1 DROP select convert (
1TEk( 1 DROP select JOIN (
1TEk1 1 DROP select JOIN 1
1TEkf 1 DROP select JOIN convert
1TEkn 1 DROP select JOIN aname
1TEks 1 DROP select JOIN "1"
1TEkv 1 DROP select JOIN @version
1TEnn 1 DROP select aname aname
1TEno 1 DROP select aname *
1TEsn 1 DROP select "1" aname
1TEso 1 DROP select "1" *
1TEvn 1 DROP select @version aname
1TEvo 1 DROP select @version *
1TTnE 1 DROP DROP aname select
1TTnT 1 DROP DROP aname DROP
1TTnk 1 DROP DROP aname JOIN
1TTnn 1 DROP DROP aname aname
1Tf() 1 DROP convert ( )
1Tf(1 1 DROP convert ( 1
1Tf(f 1 DROP convert ( convert
1Tf(n 1 DROP convert ( aname
1Tf(s 1 DROP convert ( "1"
1Tf(v 1 DROP convert ( @version
1Tn(1 1 DROP aname ( 1
1Tn(f 1 DROP aname ( convert
1Tn(s 1 DROP aname ( "1"
1Tn(v 1 DROP aname ( @version
1Tn1c 1 DROP aname 1  -- comment
1Tn1o 1 DROP aname 1 *
1Tn;E 1 DROP aname ; select
1Tn;T 1 DROP aname ; DROP
1Tn;n 1 DROP aname ; aname
1TnE( 1 DROP aname select (
1TnE1 1 DROP aname select 1
1TnEf 1 DROP aname select convert
1TnEn 1 DROP aname select aname
1TnEs 1 DROP aname select "1"
1TnEv 1 DROP aname select @version
1TnT( 1 DROP aname DROP (
1TnT1 1 DROP aname DROP 1
1TnTf 1 DROP aname DROP convert
1TnTn 1 DROP aname DROP aname
1TnTs 1 DROP aname DROP "1"
1TnTv 1 DROP aname DROP @version
1Tnf( 1 DROP aname convert (
1Tnkn 1 DROP aname JOIN aname
1Tnn: 1 DROP aname aname :
1Tnnc 1 DROP aname aname  -- comment
1Tnno 1 DROP aname aname *
1Tno( 1 DROP aname * (
1Tnof 1 DROP aname * convert
1Tnos 1 DROP aname * "1"
1Tnov 1 DROP aname * @version
1Tnsc 1 DROP aname "1"  -- comment
1Tnso 1 DROP aname "1" *
1Tnvc 1 DROP aname @version  -- comment
1Tnvo 1 DROP aname @version *
1Ts(f 1 DROP "1" ( convert
1Tso( 1 DROP "1" * (
1Tso1 1 DROP "1" * 1
1Tsof 1 DROP "1" * convert
1Tson 1 DROP "1" * aname
1Tsos 1 DROP "1" * "1"
1Tsov 1 DROP "1" * @version
1Tv(1 1 DROP @version ( 1
1Tv(f 1 DROP @version ( convert
1Tvo( 1 DROP @version * (
1Tvof 1 DROP @version * convert
1Tvos 1 DROP @version * "1"
1U 1 union
1U(1) 1 union ( 1 )
1U(1o 1 union ( 1 *
1U(E( 1 union ( select (
1U(E1 1 union ( select 1
1U(Ef 1 union ( select convert
1U(Ek 1 union ( select JOIN
1U(En 1 union ( select aname
1U(Es 1 union ( select "1"
1U(Ev 1 union ( select @version
1U(f( 1 union ( convert (
1U(n) 1 union ( aname )
1U(no 1 union ( aname *
1U(s) 1 union ( "1" )
1U(so 1 union ( "1" *
1U(v) 1 union ( @version )
1U(vo 1 union ( @version *
1U1,( 1 union 1 , (
1U1,f 1 union 1 , convert
1U1c 1 union 1  -- comment
1U1o( 1 union 1 * (
1U1of 1 union 1 * convert
1U1os 1 union 1 * "1"
1U1ov 1 union 1 * @version
1U; 1 union ;
1U;c 1 union ;  -- comment
1UE 1 union select
1UE(1 1 union select ( 1
1UE(E 1 union select ( select
1UE(f 1 union select ( convert
1UE(n 1 union select ( aname
1UE(o 1 union select ( *
1UE(s 1 union select ( "1"
1UE(v 1 union select ( @version
1UE1 1 union select 1
1UE1& 1 union select 1 and
1UE1( 1 union select 1 (
1UE1) 1 union select 1 )
1UE1, 1 union select 1 ,
1UE1; 1 union select 1 ;
1UE1B 1 union select 1 group by
1UE1U 1 union select 1 union
1UE1c 1 union select 1  -- comment
1UE1f 1 union select 1 convert
1UE1k 1 union select 1 JOIN
1UE1n 1 union select 1 aname
1UE1o 1 union select 1 *
1UE1s 1 union select 1 "1"
1UE1v 1 union select 1 @version
1UE; 1 union select ;
1UE;c 1 union select ;  -- comment
1UEc 1 union select  -- comment
1UEf 1 union select convert
1UEf( 1 union select convert (
1UEf, 1 union select convert ,
1UEf; 1 union select convert ;
1UEfc 1 union select convert  -- comment
1UEk 1 union select JOIN
1UEk( 1 union select JOIN (
1UEk1 1 union select JOIN 1
1UEk; 1 union select JOIN ;
1UEkc 1 union select JOIN  -- comment
1UEkf 1 union select JOIN convert
1UEkn 1 union select JOIN aname
1UEko 1 union select JOIN *
1UEks 1 union select JOIN "1"
1UEkv 1 union select JOIN @version
1UEn 1 union select aname
1UEn& 1 union select aname and
1UEn( 1 union select aname (
1UEn) 1 union select aname )
1UEn, 1 union select aname ,
1UEn1 1 union select aname 1
1UEn; 1 union select aname ;
1UEnB 1 union select aname group by
1UEnU 1 union select aname union
1UEnc 1 union select aname  -- comment
1UEnf 1 union select aname convert
1UEnk 1 union select aname JOIN
1UEnn 1 union select aname aname
1UEno 1 union select aname *
1UEns 1 union select aname "1"
1UEok 1 union select * JOIN
1UEon 1 union select * aname
1UEs 1 union select "1"
1UEs& 1 union select "1" and
1UEs( 1 union select "1" (
1UEs) 1 union select "1" )
1UEs, 1 union select "1" ,
1UEs1 1 union select "1" 1
1UEs; 1 union select "1" ;
1UEsB 1 union select "1" group by
1UEsU 1 union select "1" union
1UEsc 1 union select "1"  -- comment
1UEsf 1 union select "1" convert
1UEsk 1 union select "1" JOIN
1UEso 1 union select "1" *
1UEsv 1 union select "1" @version
1UEv 1 union select @version
1UEv& 1 union select @version and
1UEv( 1 union select @version (
1UEv) 1 union select @version )
1UEv, 1 union select @version ,
1UEv; 1 union select @version ;
1UEvB 1 union select @version group by
1UEvU 1 union select @version union
1UEvc 1 union select @version  -- comment
1UEvf 1 union select @version convert
1UEvk 1 union select @version JOIN
1UEvn 1 union select @version aname
1UEvo 1 union select @version *
1UEvs 1 union select @version "1"
1UTn( 1 union DROP aname (
1UTn1 1 union DROP aname 1
1UTnf 1 union DROP aname convert
1UTnn 1 union DROP aname aname
1UTns 1 union DROP aname "1"
1UTnv 1 union DROP aname @version
1Uc 1 union  -- comment
1Uf() 1 union convert ( )
1Uf(1 1 union convert ( 1
1Uf(f 1 union convert ( convert
1Uf(n 1 union convert ( aname
1Uf(s 1 union convert ( "1"
1Uf(v 1 union convert ( @version
1Uk(E 1 union JOIN ( select
1Uo(E 1 union * ( select
1Uon( 1 union * aname (
1Uon1 1 union * aname 1
1Uonf 1 union * aname convert
1Uons 1 union * aname "1"
1Us,( 1 union "1" , (
1Us,f 1 union "1" , convert
1Usc 1 union "1"  -- comment
1Uso( 1 union "1" * (
1Uso1 1 union "1" * 1
1Usof 1 union "1" * convert
1Uson 1 union "1" * aname
1Usos 1 union "1" * "1"
1Usov 1 union "1" * @version
1Uv,( 1 union @version , (
1Uv,f 1 union @version , convert
1Uvc 1 union @version  -- comment
1Uvo( 1 union @version * (
1Uvof 1 union @version * convert
1Uvos 1 union @version * "1"
1c 1  -- comment
1f()1 1 convert ( ) 1
1f()U 1 convert ( ) union
1f()f 1 convert ( ) convert
1f()k 1 convert ( ) JOIN
1f()n 1 convert ( ) aname
1f()o 1 convert ( ) *
1f()s 1 convert ( ) "1"
1f()v 1 convert ( ) @version
1f(1) 1 convert ( 1 )
1f(1n 1 convert ( 1 aname
1f(1o 1 convert ( 1 *
1f(E( 1 convert ( select (
1f(E1 1 convert ( select 1
1f(Ef 1 convert ( select convert
1f(Ek 1 convert ( select JOIN
1f(En 1 convert ( select aname
1f(Es 1 convert ( select "1"
1f(Ev 1 convert ( select @version
1f(f( 1 convert ( convert (
1f(n) 1 convert ( aname )
1f(n, 1 convert ( aname ,
1f(no 1 convert ( aname *
1f(s) 1 convert ( "1" )
1f(so 1 convert ( "1" *
1f(v) 1 convert ( @version )
1f(vo 1 convert ( @version *
1k(1o 1 JOIN ( 1 *
1k(f( 1 JOIN ( convert (
1k(n) 1 JOIN ( aname )
1k(no 1 JOIN ( aname *
1k(s) 1 JOIN ( "1" )
1k(so 1 JOIN ( "1" *
1k(v) 1 JOIN ( @version )
1k(vo 1 JOIN ( @version *
1k)&( 1 JOIN ) and (
1k)&1 1 JOIN ) and 1
1k)&f 1 JOIN ) and convert
1k)&n 1 JOIN ) and aname
1k)&s 1 JOIN ) and "1"
1k)&v 1 JOIN ) and @version
1k);E 1 JOIN ) ; select
1k);T 1 JOIN ) ; DROP
1k)B( 1 JOIN ) group by (
1k)B1 1 JOIN ) group by 1
1k)Bf 1 JOIN ) group by convert
1k)Bn 1 JOIN ) group by aname
1k)Bs 1 JOIN ) group by "1"
1k)Bv 1 JOIN ) group by @version
1k)E( 1 JOIN ) select (
1k)E1 1 JOIN ) select 1
1k)Ef 1 JOIN ) select convert
1k)Ek 1 JOIN ) select JOIN
1k)En 1 JOIN ) select aname
1k)Es 1 JOIN ) select "1"
1k)Ev 1 JOIN ) select @version
1k)UE 1 JOIN ) union select
1k)f( 1 JOIN ) convert (
1k)o( 1 JOIN ) * (
1k)of 1 JOIN ) * convert
1k1 1 JOIN 1
1k1&( 1 JOIN 1 and (
1k1&1 1 JOIN 1 and 1
1k1&f 1 JOIN 1 and convert
1k1&n 1 JOIN 1 and aname
1k1&s 1 JOIN 1 and "1"
1k1&v 1 JOIN 1 and @version
1k1; 1 JOIN 1 ;
1k1;E 1 JOIN 1 ; select
1k1;T 1 JOIN 1 ; DROP
1k1;c 1 JOIN 1 ;  -- comment
1k1B( 1 JOIN 1 group by (
1k1B1 1 JOIN 1 group by 1
1k1Bf 1 JOIN 1 group by convert
1k1Bn 1 JOIN 1 group by aname
1k1Bs 1 JOIN 1 group by "1"
1k1Bv 1 JOIN 1 group by @version
1k1E( 1 JOIN 1 select (
1k1E1 1 JOIN 1 select 1
1k1Ef 1 JOIN 1 select convert
1k1Ek 1 JOIN 1 select JOIN
1k1En 1 JOIN 1 select aname
1k1Es 1 JOIN 1 select "1"
1k1Ev 1 JOIN 1 select @version
1k1U( 1 JOIN 1 union (
1k1UE 1 JOIN 1 union select
1k1c 1 JOIN 1  -- comment
1k1o( 1 JOIN 1 * (
1k1of 1 JOIN 1 * convert
1k1os 1 JOIN 1 * "1"
1k1ov 1 JOIN 1 * @version
1kUE( 1 JOIN union select (
1kUE1 1 JOIN union select 1
1kUEf 1 JOIN union select convert
1kUEk 1 JOIN union select JOIN
1kUEn 1 JOIN union select aname
1kUEs 1 JOIN union select "1"
1kUEv 1 JOIN union select @version
1kf() 1 JOIN convert ( )
1kf(1 1 JOIN convert ( 1
1kf(f 1 JOIN convert ( convert
1kf(n 1 JOIN convert ( aname
1kf(s 1 JOIN convert ( "1"
1kf(v 1 JOIN convert ( @version
1kn 1 JOIN aname
1kn&( 1 JOIN aname and (
1kn&1 1 JOIN aname and 1
1kn&f 1 JOIN aname and convert
1kn&n 1 JOIN aname and aname
1kn&s 1 JOIN aname and "1"
1kn&v 1 JOIN aname and @version
1kn; 1 JOIN aname ;
1kn;E 1 JOIN aname ; select
1kn;T 1 JOIN aname ; DROP
1kn;c 1 JOIN aname ;  -- comment
1knB( 1 JOIN aname group by (
1knB1 1 JOIN aname group by 1
1knBf 1 JOIN aname group by convert
1knBn 1 JOIN aname group by aname
1knBs 1 JOIN aname group by "1"
1knBv 1 JOIN aname group by @version
1knE( 1 JOIN aname select (
1knE1 1 JOIN aname select 1
1knEf 1 JOIN aname select convert
1knEn 1 JOIN aname select aname
1knEs 1 JOIN aname select "1"
1knEv 1 JOIN aname select @version
1knU( 1 JOIN aname union (
1knUE 1 JOIN aname union select
1knc 1 JOIN aname  -- comment
1ks 1 JOIN "1"
1ks&( 1 JOIN "1" and (
1ks&1 1 JOIN "1" and 1
1ks&f 1 JOIN "1" and convert
1ks&n 1 JOIN "1" and aname
1ks&s 1 JOIN "1" and "1"
1ks&v 1 JOIN "1" and @version
1ks; 1 JOIN "1" ;
1ks;E 1 JOIN "1" ; select
1ks;T 1 JOIN "1" ; DROP
1ks;c 1 JOIN "1" ;  -- comment
1ksB( 1 JOIN "1" group by (
1ksB1 1 JOIN "1" group by 1
1ksBf 1 JOIN "1" group by convert
1ksBn 1 JOIN "1" group by aname
1ksBs 1 JOIN "1" group by "1"
1ksBv 1 JOIN "1" group by @version
1ksE( 1 JOIN "1" select (
1ksE1 1 JOIN "1" select 1
1ksEf 1 JOIN "1" select convert
1ksEk 1 JOIN "1" select JOIN
1ksEn 1 JOIN "1" select aname
1ksEs 1 JOIN "1" select "1"
1ksEv 1 JOIN "1" select @version
1ksU( 1 JOIN "1" union (
1ksUE 1 JOIN "1" union select
1ksc 1 JOIN "1"  -- comment
1kso( 1 JOIN "1" * (
1kso1 1 JOIN "1" * 1
1ksof 1 JOIN "1" * convert
1kson 1 JOIN "1" * aname
1ksos 1 JOIN "1" * "1"
1ksov 1 JOIN "1" * @version
1kv 1 JOIN @version
1kv&( 1 JOIN @version and (
1kv&1 1 JOIN @version and 1
1kv&f 1 JOIN @version and convert
1kv&n 1 JOIN @version and aname
1kv&s 1 JOIN @version and "1"
1kv&v 1 JOIN @version and @version
1kv; 1 JOIN @version ;
1kv;E 1 JOIN @version ; select
1kv;T 1 JOIN @version ; DROP
1kv;c 1 JOIN @version ;  -- comment
1kvB( 1 JOIN @version group by (
1kvB1 1 JOIN @version group by 1
1kvBf 1 JOIN @version group by convert
1kvBn 1 JOIN @version group by aname
1kvBs 1 JOIN @version group by "1"
1kvBv 1 JOIN @version group by @version
1kvE( 1 JOIN @version select (
1kvE1 1 JOIN @version select 1
1kvEf 1 JOIN @version select convert
1kvEk 1 JOIN @version select JOIN
1kvEn 1 JOIN @version select aname
1kvEs 1 JOIN @version select "1"
1kvEv 1 JOIN @version select @version
1kvU( 1 JOIN @version union (
1kvUE 1 JOIN @version union select
1kvc 1 JOIN @version  -- comment
1kvo( 1 JOIN @version * (
1kvof 1 JOIN @version * convert
1kvos 1 JOIN @version * "1"
1n&f( 1 aname and convert (
1n(1o 1 aname ( 1 *
1n(f( 1 aname ( convert (
1n(s) 1 aname ( "1" )
1n(so 1 aname ( "1" *
1n(v) 1 aname ( @version )
1n(vo 1 aname ( @version *
1n)UE 1 aname ) union select
1n,f( 1 aname , convert (
1nE(1 1 aname select ( 1
1nE(f 1 aname select ( convert
1nE(n 1 aname select ( aname
1nE(s 1 aname select ( "1"
1nE(v 1 aname select ( @version
1nE1c 1 aname select 1  -- comment
1nE1o 1 aname select 1 *
1nEf( 1 aname select convert (
1nEnc 1 aname select aname  -- comment
1nEno 1 aname select aname *
1nEsc 1 aname select "1"  -- comment
1nEso 1 aname select "1" *
1nEvc 1 aname select @version  -- comment
1nEvo 1 aname select @version *
1nU(E 1 aname union ( select
1nUE 1 aname union select
1nUE( 1 aname union select (
1nUE1 1 aname union select 1
1nUE; 1 aname union select ;
1nUEc 1 aname union select  -- comment
1nUEf 1 aname union select convert
1nUEk 1 aname union select JOIN
1nUEn 1 aname union select aname
1nUEs 1 aname union select "1"
1nUEv 1 aname union select @version
1o(1& 1 * ( 1 and
1o(1) 1 * ( 1 )
1o(1, 1 * ( 1 ,
1o(1o 1 * ( 1 *
1o(E( 1 * ( select (
1o(E1 1 * ( select 1
1o(EE 1 * ( select select
1o(Ef 1 * ( select convert
1o(Ek 1 * ( select JOIN
1o(En 1 * ( select aname
1o(Eo 1 * ( select *
1o(Es 1 * ( select "1"
1o(Ev 1 * ( select @version
1o(f( 1 * ( convert (
1o(n& 1 * ( aname and
1o(n) 1 * ( aname )
1o(n, 1 * ( aname ,
1o(no 1 * ( aname *
1o(s& 1 * ( "1" and
1o(s) 1 * ( "1" )
1o(s, 1 * ( "1" ,
1o(so 1 * ( "1" *
1o(v& 1 * ( @version and
1o(v) 1 * ( @version )
1o(v, 1 * ( @version ,
1o(vo 1 * ( @version *
1oU(E 1 * union ( select
1oUEk 1 * union select JOIN
1oUEn 1 * union select aname
1of() 1 * convert ( )
1of(1 1 * convert ( 1
1of(E 1 * convert ( select
1of(f 1 * convert ( convert
1of(n 1 * convert ( aname
1of(s 1 * convert ( "1"
1of(v 1 * convert ( @version
1ok&( 1 * JOIN and (
1ok&1 1 * JOIN and 1
1ok&f 1 * JOIN and convert
1ok&n 1 * JOIN and aname
1ok&s 1 * JOIN and "1"
1ok&v 1 * JOIN and @version
1ok(1 1 * JOIN ( 1
1ok(f 1 * JOIN ( convert
1ok(n 1 * JOIN ( aname
1ok(s 1 * JOIN ( "1"
1ok(v 1 * JOIN ( @version
1ok1c 1 * JOIN 1  -- comment
1ok1o 1 * JOIN 1 *
1okf( 1 * JOIN convert (
1oknc 1 * JOIN aname  -- comment
1oko( 1 * JOIN * (
1oko1 1 * JOIN * 1
1okof 1 * JOIN * convert
1okon 1 * JOIN * aname
1okos 1 * JOIN * "1"
1okov 1 * JOIN * @version
1oksc 1 * JOIN "1"  -- comment
1okso 1 * JOIN "1" *
1okvc 1 * JOIN @version  -- comment
1okvo 1 * JOIN @version *
1onsU 1 * aname "1" union
1os&( 1 * "1" and (
1os&1 1 * "1" and 1
1os&E 1 * "1" and select
1os&U 1 * "1" and union
1os&f 1 * "1" and convert
1os&k 1 * "1" and JOIN
1os&n 1 * "1" and aname
1os&s 1 * "1" and "1"
1os&v 1 * "1" and @version
1os(E 1 * "1" ( select
1os(U 1 * "1" ( union
1os)& 1 * "1" ) and
1os), 1 * "1" ) ,
1os); 1 * "1" ) ;
1os)B 1 * "1" ) group by
1os)E 1 * "1" ) select
1os)U 1 * "1" ) union
1os)c 1 * "1" )  -- comment
1os)f 1 * "1" ) convert
1os)k 1 * "1" ) JOIN
1os)o 1 * "1" ) *
1os,( 1 * "1" , (
1os,f 1 * "1" , convert
1os1( 1 * "1" 1 (
1os1U 1 * "1" 1 union
1os1f 1 * "1" 1 convert
1os1n 1 * "1" 1 aname
1os1s 1 * "1" 1 "1"
1os1v 1 * "1" 1 @version
1os; 1 * "1" ;
1os;E 1 * "1" ; select
1os;T 1 * "1" ; DROP
1os;c 1 * "1" ;  -- comment
1os;n 1 * "1" ; aname
1osA( 1 * "1" COLLATE (
1osAf 1 * "1" COLLATE convert
1osAs 1 * "1" COLLATE "1"
1osAt 1 * "1" COLLATE binary
1osAv 1 * "1" COLLATE @version
1osB( 1 * "1" group by (
1osB1 1 * "1" group by 1
1osBE 1 * "1" group by select
1osBf 1 * "1" group by convert
1osBn 1 * "1" group by aname
1osBs 1 * "1" group by "1"
1osBv 1 * "1" group by @version
1osE( 1 * "1" select (
1osE1 1 * "1" select 1
1osEU 1 * "1" select union
1osEf 1 * "1" select convert
1osEk 1 * "1" select JOIN
1osEn 1 * "1" select aname
1osEo 1 * "1" select *
1osEs 1 * "1" select "1"
1osEv 1 * "1" select @version
1osT( 1 * "1" DROP (
1osT1 1 * "1" DROP 1
1osTE 1 * "1" DROP select
1osTT 1 * "1" DROP DROP
1osTf 1 * "1" DROP convert
1osTn 1 * "1" DROP aname
1osTs 1 * "1" DROP "1"
1osTv 1 * "1" DROP @version
1osU 1 * "1" union
1osU( 1 * "1" union (
1osU1 1 * "1" union 1
1osU; 1 * "1" union ;
1osUE 1 * "1" union select
1osUT 1 * "1" union DROP
1osUc 1 * "1" union  -- comment
1osUf 1 * "1" union convert
1osUk 1 * "1" union JOIN
1osUo 1 * "1" union *
1osUs 1 * "1" union "1"
1osUv 1 * "1" union @version
1osc 1 * "1"  -- comment
1osf( 1 * "1" convert (
1osk( 1 * "1" JOIN (
1osk) 1 * "1" JOIN )
1osk1 1 * "1" JOIN 1
1oskB 1 * "1" JOIN group by
1oskU 1 * "1" JOIN union
1oskf 1 * "1" JOIN convert
1oskn 1 * "1" JOIN aname
1osks 1 * "1" JOIN "1"
1oskv 1 * "1" JOIN @version
1osv( 1 * "1" @version (
1osvU 1 * "1" @version union
1osvf 1 * "1" @version convert
1osvo 1 * "1" @version *
1osvs 1 * "1" @version "1"
1ov 1 * @version
1ov&( 1 * @version and (
1ov&1 1 * @version and 1
1ov&E 1 * @version and select
1ov&U 1 * @version and union
1ov&f 1 * @version and convert
1ov&k 1 * @version and JOIN
1ov&n 1 * @version and aname
1ov&s 1 * @version and "1"
1ov&v 1 * @version and @version
1ov(E 1 * @version ( select
1ov(U 1 * @version ( union
1ov)& 1 * @version ) and
1ov), 1 * @version ) ,
1ov); 1 * @version ) ;
1ov)B 1 * @version ) group by
1ov)E 1 * @version ) select
1ov)U 1 * @version ) union
1ov)c 1 * @version )  -- comment
1ov)f 1 * @version ) convert
1ov)k 1 * @version ) JOIN
1ov)o 1 * @version ) *
1ov,( 1 * @version , (
1ov,f 1 * @version , convert
1ov; 1 * @version ;
1ov;E 1 * @version ; select
1ov;T 1 * @version ; DROP
1ov;c 1 * @version ;  -- comment
1ov;n 1 * @version ; aname
1ovA( 1 * @version COLLATE (
1ovAf 1 * @version COLLATE convert
1ovAs 1 * @version COLLATE "1"
1ovAt 1 * @version COLLATE binary
1ovAv 1 * @version COLLATE @version
1ovB( 1 * @version group by (
1ovB1 1 * @version group by 1
1ovBE 1 * @version group by select
1ovBf 1 * @version group by convert
1ovBn 1 * @version group by aname
1ovBs 1 * @version group by "1"
1ovBv 1 * @version group by @version
1ovE( 1 * @version select (
1ovE1 1 * @version select 1
1ovEU 1 * @version select union
1ovEf 1 * @version select convert
1ovEk 1 * @version select JOIN
1ovEn 1 * @version select aname
1ovEo 1 * @version select *
1ovEs 1 * @version select "1"
1ovEv 1 * @version select @version
1ovT( 1 * @version DROP (
1ovT1 1 * @version DROP 1
1ovTE 1 * @version DROP select
1ovTT 1 * @version DROP DROP
1ovTf 1 * @version DROP convert
1ovTn 1 * @version DROP aname
1ovTs 1 * @version DROP "1"
1ovTv 1 * @version DROP @version
1ovU 1 * @version union
1ovU( 1 * @version union (
1ovU1 1 * @version union 1
1ovU; 1 * @version union ;
1ovUE 1 * @version union select
1ovUT 1 * @version union DROP
1ovUc 1 * @version union  -- comment
1ovUf 1 * @version union convert
1ovUk 1 * @version union JOIN
1ovUo 1 * @version union *
1ovUs 1 * @version union "1"
1ovUv 1 * @version union @version
1ovc 1 * @version  -- comment
1ovf( 1 * @version convert (
1ovk( 1 * @version JOIN (
1ovk) 1 * @version JOIN )
1ovk1 1 * @version JOIN 1
1ovkB 1 * @version JOIN group by
1ovkU 1 * @version JOIN union
1ovkf 1 * @version JOIN convert
1ovkn 1 * @version JOIN aname
1ovks 1 * @version JOIN "1"
1ovkv 1 * @version JOIN @version
1ovo( 1 * @version * (
1ovoU 1 * @version * union
1ovof 1 * @version * convert
1ovok 1 * @version * JOIN
1ovos 1 * @version * "1"
1ovs( 1 * @version "1" (
1ovs1 1 * @version "1" 1
1ovsU 1 * @version "1" union
1ovsf 1 * @version "1" convert
1ovso 1 * @version "1" *
1ovsv 1 * @version "1" @version
1sUE 1 "1" union select
1sUE; 1 "1" union select ;
1sUEc 1 "1" union select  -- comment
1sUEk 1 "1" union select JOIN
1sf() 1 "1" convert ( )
1sf(1 1 "1" convert ( 1
1sf(f 1 "1" convert ( convert
1sf(n 1 "1" convert ( aname
1sf(s 1 "1" convert ( "1"
1sf(v 1 "1" convert ( @version
1sv 1 "1" @version
1sv; 1 "1" @version ;
1sv;c 1 "1" @version ;  -- comment
1svc 1 "1" @version  -- comment
1svo( 1 "1" @version * (
1svof 1 "1" @version * convert
1svos 1 "1" @version * "1"
1vUE 1 @version union select
1vUE; 1 @version union select ;
1vUEc 1 @version union select  -- comment
1vUEk 1 @version union select JOIN
1vf() 1 @version convert ( )
1vf(1 1 @version convert ( 1
1vf(f 1 @version convert ( convert
1vf(n 1 @version convert ( aname
1vf(s 1 @version convert ( "1"
1vf(v 1 @version convert ( @version
1vo(1 1 @version * ( 1
1vo(f 1 @version * ( convert
1vo(n 1 @version * ( aname
1vo(s 1 @version * ( "1"
1vo(v 1 @version * ( @version
1vof( 1 @version * convert (
1vos( 1 @version * "1" (
1vos1 1 @version * "1" 1
1vosU 1 @version * "1" union
1vosf 1 @version * "1" convert
1vosv 1 @version * "1" @version
1vs 1 @version "1"
1vs; 1 @version "1" ;
1vs;c 1 @version "1" ;  -- comment
1vsc 1 @version "1"  -- comment
1vso( 1 @version "1" * (
1vso1 1 @version "1" * 1
1vsof 1 @version "1" * convert
1vson 1 @version "1" * aname
1vsos 1 @version "1" * "1"
1vsov 1 @version "1" * @version
;T(Ef ; DROP ( select convert
;T(Ek ; DROP ( select JOIN
;Tknc ; DROP JOIN aname  -- comment
E(1&( select ( 1 and (
E(1&1 select ( 1 and 1
E(1&f select ( 1 and convert
E(1&n select ( 1 and aname
E(1&s select ( 1 and "1"
E(1&v select ( 1 and @version
E(1)& select ( 1 ) and
E(1), select ( 1 ) ,
E(1)1 select ( 1 ) 1
E(1); select ( 1 ) ;
E(1)B select ( 1 ) group by
E(1)U select ( 1 ) union
E(1)c select ( 1 )  -- comment
E(1)f select ( 1 ) convert
E(1)k select ( 1 ) JOIN
E(1)n select ( 1 ) aname
E(1)o select ( 1 ) *
E(1)s select ( 1 ) "1"
E(1)v select ( 1 ) @version
E(1,f select ( 1 , convert
E(1f( select ( 1 convert (
E(1n) select ( 1 aname )
E(1o( select ( 1 * (
E(1of select ( 1 * convert
E(1os select ( 1 * "1"
E(1ov select ( 1 * @version
E(1s) select ( 1 "1" )
E(1v) select ( 1 @version )
E(1vo select ( 1 @version *
E(E(1 select ( select ( 1
E(E(E select ( select ( select
E(E(f select ( select ( convert
E(E(n select ( select ( aname
E(E(s select ( select ( "1"
E(E(v select ( select ( @version
E(E1& select ( select 1 and
E(E1) select ( select 1 )
E(E1o select ( select 1 *
E(Ef( select ( select convert (
E(Ek( select ( select JOIN (
E(Ek1 select ( select JOIN 1
E(Ekf select ( select JOIN convert
E(Ekn select ( select JOIN aname
E(Eks select ( select JOIN "1"
E(Ekv select ( select JOIN @version
E(En& select ( select aname and
E(En) select ( select aname )
E(Eno select ( select aname *
E(Es& select ( select "1" and
E(Es) select ( select "1" )
E(Eso select ( select "1" *
E(Ev& select ( select @version and
E(Ev) select ( select @version )
E(Evo select ( select @version *
E(f() select ( convert ( )
E(f(1 select ( convert ( 1
E(f(E select ( convert ( select
E(f(f select ( convert ( convert
E(f(n select ( convert ( aname
E(f(s select ( convert ( "1"
E(f(v select ( convert ( @version
E(n&( select ( aname and (
E(n&1 select ( aname and 1
E(n&f select ( aname and convert
E(n&n select ( aname and aname
E(n&s select ( aname and "1"
E(n&v select ( aname and @version
E(n(1 select ( aname ( 1
E(n(f select ( aname ( convert
E(n(s select ( aname ( "1"
E(n(v select ( aname ( @version
E(n)& select ( aname ) and
E(n), select ( aname ) ,
E(n)1 select ( aname ) 1
E(n); select ( aname ) ;
E(n)B select ( aname ) group by
E(n)U select ( aname ) union
E(n)c select ( aname )  -- comment
E(n)f select ( aname ) convert
E(n)k select ( aname ) JOIN
E(n)n select ( aname ) aname
E(n)o select ( aname ) *
E(n)s select ( aname ) "1"
E(n)v select ( aname ) @version
E(n,f select ( aname , convert
E(n1) select ( aname 1 )
E(n1o select ( aname 1 *
E(nf( select ( aname convert (
E(no( select ( aname * (
E(nof select ( aname * convert
E(nos select ( aname * "1"
E(nov select ( aname * @version
E(s&( select ( "1" and (
E(s&1 select ( "1" and 1
E(s&f select ( "1" and convert
E(s&n select ( "1" and aname
E(s&s select ( "1" and "1"
E(s&v select ( "1" and @version
E(s)& select ( "1" ) and
E(s), select ( "1" ) ,
E(s)1 select ( "1" ) 1
E(s); select ( "1" ) ;
E(s)B select ( "1" ) group by
E(s)U select ( "1" ) union
E(s)c select ( "1" )  -- comment
E(s)f select ( "1" ) convert
E(s)k select ( "1" ) JOIN
E(s)n select ( "1" ) aname
E(s)o select ( "1" ) *
E(s)s select ( "1" ) "1"
E(s)v select ( "1" ) @version
E(s,f select ( "1" , convert
E(s1) select ( "1" 1 )
E(sf( select ( "1" convert (
E(so( select ( "1" * (
E(so1 select ( "1" * 1
E(sof select ( "1" * convert
E(son select ( "1" * aname
E(sos select ( "1" * "1"
E(sov select ( "1" * @version
E(sv) select ( "1" @version )
E(svo select ( "1" @version *
E(v&( select ( @version and (
E(v&1 select ( @version and 1
E(v&f select ( @version and convert
E(v&n select ( @version and aname
E(v&s select ( @version and "1"
E(v&v select ( @version and @version
E(v)& select ( @version ) and
E(v), select ( @version ) ,
E(v)1 select ( @version ) 1
E(v); select ( @version ) ;
E(v)B select ( @version ) group by
E(v)U select ( @version ) union
E(v)c select ( @version )  -- comment
E(v)f select ( @version ) convert
E(v)k select ( @version ) JOIN
E(v)n select ( @version ) aname
E(v)o select ( @version ) *
E(v)s select ( @version ) "1"
E(v)v select ( @version ) @version
E(v,f select ( @version , convert
E(vf( select ( @version convert (
E(vo( select ( @version * (
E(vof select ( @version * convert
E(vos select ( @version * "1"
E(vs) select ( @version "1" )
E(vso select ( @version "1" *
E1&(1 select 1 and ( 1
E1&(E select 1 and ( select
E1&(f select 1 and ( convert
E1&(n select 1 and ( aname
E1&(s select 1 and ( "1"
E1&(v select 1 and ( @version
E1&1) select 1 and 1 )
E1&1o select 1 and 1 *
E1&f( select 1 and convert (
E1&n) select 1 and aname )
E1&no select 1 and aname *
E1&s) select 1 and "1" )
E1&so select 1 and "1" *
E1&v) select 1 and @version )
E1&vo select 1 and @version *
E1) select 1 )
E1)&( select 1 ) and (
E1)&1 select 1 ) and 1
E1)&f select 1 ) and convert
E1)&n select 1 ) and aname
E1)&s select 1 ) and "1"
E1)&v select 1 ) and @version
E1); select 1 ) ;
E1);( select 1 ) ; (
E1);E select 1 ) ; select
E1);T select 1 ) ; DROP
E1);c select 1 ) ;  -- comment
E1)UE select 1 ) union select
E1)c select 1 )  -- comment
E1)kn select 1 ) JOIN aname
E1)o( select 1 ) * (
E1)o1 select 1 ) * 1
E1)of select 1 ) * convert
E1)on select 1 ) * aname
E1)os select 1 ) * "1"
E1)ov select 1 ) * @version
E1,(1 select 1 , ( 1
E1,(f select 1 , ( convert
E1,(n select 1 , ( aname
E1,(s select 1 , ( "1"
E1,(v select 1 , ( @version
E1,f( select 1 , convert (
E1;(E select 1 ; ( select
E1B(1 select 1 group by ( 1
E1B(f select 1 group by ( convert
E1B(n select 1 group by ( aname
E1B(s select 1 group by ( "1"
E1B(v select 1 group by ( @version
E1B1) select 1 group by 1 )
E1B1o select 1 group by 1 *
E1Bf( select 1 group by convert (
E1Bn) select 1 group by aname )
E1Bno select 1 group by aname *
E1Bs) select 1 group by "1" )
E1Bso select 1 group by "1" *
E1Bv) select 1 group by @version )
E1Bvo select 1 group by @version *
E1U(E select 1 union ( select
E1UE( select 1 union select (
E1UE1 select 1 union select 1
E1UEf select 1 union select convert
E1UEk select 1 union select JOIN
E1UEn select 1 union select aname
E1UEs select 1 union select "1"
E1UEv select 1 union select @version
E1f() select 1 convert ( )
E1f(1 select 1 convert ( 1
E1f(f select 1 convert ( convert
E1f(n select 1 convert ( aname
E1f(s select 1 convert ( "1"
E1f(v select 1 convert ( @version
E1k(1 select 1 JOIN ( 1
E1k(E select 1 JOIN ( select
E1k(f select 1 JOIN ( convert
E1k(n select 1 JOIN ( aname
E1k(s select 1 JOIN ( "1"
E1k(v select 1 JOIN ( @version
E1k1) select 1 JOIN 1 )
E1k1k select 1 JOIN 1 JOIN
E1k1o select 1 JOIN 1 *
E1kf( select 1 JOIN convert (
E1kn select 1 JOIN aname
E1kn) select 1 JOIN aname )
E1kn; select 1 JOIN aname ;
E1knU select 1 JOIN aname union
E1knc select 1 JOIN aname  -- comment
E1knk select 1 JOIN aname JOIN
E1ks) select 1 JOIN "1" )
E1ksk select 1 JOIN "1" JOIN
E1kso select 1 JOIN "1" *
E1kv) select 1 JOIN @version )
E1kvk select 1 JOIN @version JOIN
E1kvo select 1 JOIN @version *
E1n)U select 1 aname ) union
E1n; select 1 aname ;
E1n;c select 1 aname ;  -- comment
E1nc select 1 aname  -- comment
E1nkn select 1 aname JOIN aname
E1o(1 select 1 * ( 1
E1o(E select 1 * ( select
E1o(f select 1 * ( convert
E1o(n select 1 * ( aname
E1o(s select 1 * ( "1"
E1o(v select 1 * ( @version
E1of( select 1 * convert (
E1os& select 1 * "1" and
E1os( select 1 * "1" (
E1os) select 1 * "1" )
E1os, select 1 * "1" ,
E1os1 select 1 * "1" 1
E1os; select 1 * "1" ;
E1osB select 1 * "1" group by
E1osU select 1 * "1" union
E1osf select 1 * "1" convert
E1osk select 1 * "1" JOIN
E1osv select 1 * "1" @version
E1ov& select 1 * @version and
E1ov( select 1 * @version (
E1ov) select 1 * @version )
E1ov, select 1 * @version ,
E1ov; select 1 * @version ;
E1ovB select 1 * @version group by
E1ovU select 1 * @version union
E1ovf select 1 * @version convert
E1ovk select 1 * @version JOIN
E1ovo select 1 * @version *
E1ovs select 1 * @version "1"
E1s; select 1 "1" ;
E1s;c select 1 "1" ;  -- comment
E1sc select 1 "1"  -- comment
E1v select 1 @version
E1v; select 1 @version ;
E1v;c select 1 @version ;  -- comment
E1vc select 1 @version  -- comment
E1vo( select 1 @version * (
E1vof select 1 @version * convert
E1vos select 1 @version * "1"
EE(f( select select ( convert (
EEk(f select select JOIN ( convert
Ef()& select convert ( ) and
Ef(), select convert ( ) ,
Ef()1 select convert ( ) 1
Ef(); select convert ( ) ;
Ef()B select convert ( ) group by
Ef()U select convert ( ) union
Ef()f select convert ( ) convert
Ef()k select convert ( ) JOIN
Ef()n select convert ( ) aname
Ef()o select convert ( ) *
Ef()s select convert ( ) "1"
Ef()v select convert ( ) @version
Ef(1& select convert ( 1 and
Ef(1) select convert ( 1 )
Ef(1, select convert ( 1 ,
Ef(1o select convert ( 1 *
Ef(E( select convert ( select (
Ef(E1 select convert ( select 1
Ef(Ef select convert ( select convert
Ef(Ek select convert ( select JOIN
Ef(En select convert ( select aname
Ef(Es select convert ( select "1"
Ef(Ev select convert ( select @version
Ef(f( select convert ( convert (
Ef(n& select convert ( aname and
Ef(n) select convert ( aname )
Ef(n, select convert ( aname ,
Ef(no select convert ( aname *
Ef(o) select convert ( * )
Ef(s& select convert ( "1" and
Ef(s) select convert ( "1" )
Ef(s, select convert ( "1" ,
Ef(so select convert ( "1" *
Ef(v& select convert ( @version and
Ef(v) select convert ( @version )
Ef(v, select convert ( @version ,
Ef(vo select convert ( @version *
Ek(1& select JOIN ( 1 and
Ek(1( select JOIN ( 1 (
Ek(1) select JOIN ( 1 )
Ek(1, select JOIN ( 1 ,
Ek(1f select JOIN ( 1 convert
Ek(1n select JOIN ( 1 aname
Ek(1o select JOIN ( 1 *
Ek(1s select JOIN ( 1 "1"
Ek(1v select JOIN ( 1 @version
Ek(E( select JOIN ( select (
Ek(E1 select JOIN ( select 1
Ek(Ef select JOIN ( select convert
Ek(Ek select JOIN ( select JOIN
Ek(En select JOIN ( select aname
Ek(Es select JOIN ( select "1"
Ek(Ev select JOIN ( select @version
Ek(f( select JOIN ( convert (
Ek(n& select JOIN ( aname and
Ek(n( select JOIN ( aname (
Ek(n) select JOIN ( aname )
Ek(n, select JOIN ( aname ,
Ek(n1 select JOIN ( aname 1
Ek(nf select JOIN ( aname convert
Ek(no select JOIN ( aname *
Ek(s& select JOIN ( "1" and
Ek(s( select JOIN ( "1" (
Ek(s) select JOIN ( "1" )
Ek(s, select JOIN ( "1" ,
Ek(s1 select JOIN ( "1" 1
Ek(sf select JOIN ( "1" convert
Ek(so select JOIN ( "1" *
Ek(sv select JOIN ( "1" @version
Ek(v& select JOIN ( @version and
Ek(v( select JOIN ( @version (
Ek(v) select JOIN ( @version )
Ek(v, select JOIN ( @version ,
Ek(vf select JOIN ( @version convert
Ek(vo select JOIN ( @version *
Ek(vs select JOIN ( @version "1"
Ek1&( select JOIN 1 and (
Ek1&1 select JOIN 1 and 1
Ek1&f select JOIN 1 and convert
Ek1&n select JOIN 1 and aname
Ek1&s select JOIN 1 and "1"
Ek1&v select JOIN 1 and @version
Ek1) select JOIN 1 )
Ek1)& select JOIN 1 ) and
Ek1); select JOIN 1 ) ;
Ek1)U select JOIN 1 ) union
Ek1)c select JOIN 1 )  -- comment
Ek1)k select JOIN 1 ) JOIN
Ek1)o select JOIN 1 ) *
Ek1,( select JOIN 1 , (
Ek1,f select JOIN 1 , convert
Ek1;( select JOIN 1 ; (
Ek1B( select JOIN 1 group by (
Ek1B1 select JOIN 1 group by 1
Ek1Bf select JOIN 1 group by convert
Ek1Bn select JOIN 1 group by aname
Ek1Bs select JOIN 1 group by "1"
Ek1Bv select JOIN 1 group by @version
Ek1U( select JOIN 1 union (
Ek1UE select JOIN 1 union select
Ek1f( select JOIN 1 convert (
Ek1k( select JOIN 1 JOIN (
Ek1k1 select JOIN 1 JOIN 1
Ek1kf select JOIN 1 JOIN convert
Ek1kn select JOIN 1 JOIN aname
Ek1ks select JOIN 1 JOIN "1"
Ek1kv select JOIN 1 JOIN @version
Ek1n select JOIN 1 aname
Ek1n) select JOIN 1 aname )
Ek1n; select JOIN 1 aname ;
Ek1nc select JOIN 1 aname  -- comment
Ek1nk select JOIN 1 aname JOIN
Ek1o( select JOIN 1 * (
Ek1of select JOIN 1 * convert
Ek1os select JOIN 1 * "1"
Ek1ov select JOIN 1 * @version
Ek1s select JOIN 1 "1"
Ek1s; select JOIN 1 "1" ;
Ek1sc select JOIN 1 "1"  -- comment
Ek1sf select JOIN 1 "1" convert
Ek1sk select JOIN 1 "1" JOIN
Ek1v select JOIN 1 @version
Ek1v; select JOIN 1 @version ;
Ek1vc select JOIN 1 @version  -- comment
Ek1vf select JOIN 1 @version convert
Ek1vk select JOIN 1 @version JOIN
Ek1vo select JOIN 1 @version *
EkE(f select JOIN select ( convert
EkEk( select JOIN select JOIN (
Ekf() select JOIN convert ( )
Ekf(1 select JOIN convert ( 1
Ekf(E select JOIN convert ( select
Ekf(f select JOIN convert ( convert
Ekf(n select JOIN convert ( aname
Ekf(o select JOIN convert ( *
Ekf(s select JOIN convert ( "1"
Ekf(v select JOIN convert ( @version
Ekn&( select JOIN aname and (
Ekn&1 select JOIN aname and 1
Ekn&f select JOIN aname and convert
Ekn&n select JOIN aname and aname
Ekn&s select JOIN aname and "1"
Ekn&v select JOIN aname and @version
Ekn(1 select JOIN aname ( 1
Ekn(f select JOIN aname ( convert
Ekn(s select JOIN aname ( "1"
Ekn(v select JOIN aname ( @version
Ekn) select JOIN aname )
Ekn)& select JOIN aname ) and
Ekn); select JOIN aname ) ;
Ekn)U select JOIN aname ) union
Ekn)c select JOIN aname )  -- comment
Ekn)k select JOIN aname ) JOIN
Ekn)o select JOIN aname ) *
Ekn,( select JOIN aname , (
Ekn,f select JOIN aname , convert
Ekn1 select JOIN aname 1
Ekn1; select JOIN aname 1 ;
Ekn1c select JOIN aname 1  -- comment
Ekn1k select JOIN aname 1 JOIN
Ekn1o select JOIN aname 1 *
Ekn;( select JOIN aname ; (
EknB( select JOIN aname group by (
EknB1 select JOIN aname group by 1
EknBf select JOIN aname group by convert
EknBn select JOIN aname group by aname
EknBs select JOIN aname group by "1"
EknBv select JOIN aname group by @version
EknU( select JOIN aname union (
EknUE select JOIN aname union select
Eknf( select JOIN aname convert (
Eknk( select JOIN aname JOIN (
Eknk1 select JOIN aname JOIN 1
Eknkf select JOIN aname JOIN convert
Eknkn select JOIN aname JOIN aname
Eknks select JOIN aname JOIN "1"
Eknkv select JOIN aname JOIN @version
Eko(1 select JOIN * ( 1
Eko(f select JOIN * ( convert
Eko(n select JOIN * ( aname
Eko(s select JOIN * ( "1"
Eko(v select JOIN * ( @version
Ekok( select JOIN * JOIN (
Ekokn select JOIN * JOIN aname
Eks&( select JOIN "1" and (
Eks&1 select JOIN "1" and 1
Eks&f select JOIN "1" and convert
Eks&n select JOIN "1" and aname
Eks&s select JOIN "1" and "1"
Eks&v select JOIN "1" and @version
Eks) select JOIN "1" )
Eks)& select JOIN "1" ) and
Eks); select JOIN "1" ) ;
Eks)U select JOIN "1" ) union
Eks)c select JOIN "1" )  -- comment
Eks)k select JOIN "1" ) JOIN
Eks)o select JOIN "1" ) *
Eks,( select JOIN "1" , (
Eks,f select JOIN "1" , convert
Eks1 select JOIN "1" 1
Eks1; select JOIN "1" 1 ;
Eks1c select JOIN "1" 1  -- comment
Eks1f select JOIN "1" 1 convert
Eks1k select JOIN "1" 1 JOIN
Eks;( select JOIN "1" ; (
EksB( select JOIN "1" group by (
EksB1 select JOIN "1" group by 1
EksBf select JOIN "1" group by convert
EksBn select JOIN "1" group by aname
EksBs select JOIN "1" group by "1"
EksBv select JOIN "1" group by @version
EksU( select JOIN "1" union (
EksUE select JOIN "1" union select
Eksf( select JOIN "1" convert (
Eksk( select JOIN "1" JOIN (
Eksk1 select JOIN "1" JOIN 1
Ekskf select JOIN "1" JOIN convert
Ekskn select JOIN "1" JOIN aname
Eksks select JOIN "1" JOIN "1"
Ekskv select JOIN "1" JOIN @version
Ekso( select JOIN "1" * (
Ekso1 select JOIN "1" * 1
Eksof select JOIN "1" * convert
Ekson select JOIN "1" * aname
Eksos select JOIN "1" * "1"
Eksov select JOIN "1" * @version
Eksv select JOIN "1" @version
Eksv; select JOIN "1" @version ;
Eksvc select JOIN "1" @version  -- comment
Eksvf select JOIN "1" @version convert
Eksvk select JOIN "1" @version JOIN
Eksvo select JOIN "1" @version *
Ekv&( select JOIN @version and (
Ekv&1 select JOIN @version and 1
Ekv&f select JOIN @version and convert
Ekv&n select JOIN @version and aname
Ekv&s select JOIN @version and "1"
Ekv&v select JOIN @version and @version
Ekv) select JOIN @version )
Ekv)& select JOIN @version ) and
Ekv); select JOIN @version ) ;
Ekv)U select JOIN @version ) union
Ekv)c select JOIN @version )  -- comment
Ekv)k select JOIN @version ) JOIN
Ekv)o select JOIN @version ) *
Ekv,( select JOIN @version , (
Ekv,f select JOIN @version , convert
Ekv;( select JOIN @version ; (
EkvB( select JOIN @version group by (
EkvB1 select JOIN @version group by 1
EkvBf select JOIN @version group by convert
EkvBn select JOIN @version group by aname
EkvBs select JOIN @version group by "1"
EkvBv select JOIN @version group by @version
EkvU( select JOIN @version union (
EkvUE select JOIN @version union select
Ekvf( select JOIN @version convert (
Ekvk( select JOIN @version JOIN (
Ekvk1 select JOIN @version JOIN 1
Ekvkf select JOIN @version JOIN convert
Ekvkn select JOIN @version JOIN aname
Ekvks select JOIN @version JOIN "1"
Ekvkv select JOIN @version JOIN @version
Ekvo( select JOIN @version * (
Ekvof select JOIN @version * convert
Ekvos select JOIN @version * "1"
Ekvs select JOIN @version "1"
Ekvs; select JOIN @version "1" ;
Ekvsc select JOIN @version "1"  -- comment
Ekvsf select JOIN @version "1" convert
Ekvsk select JOIN @version "1" JOIN
Ekvso select JOIN @version "1" *
En&(1 select aname and ( 1
En&(E select aname and ( select
En&(f select aname and ( convert
En&(n select aname and ( aname
En&(s select aname and ( "1"
En&(v select aname and ( @version
En&1) select aname and 1 )
En&1o select aname and 1 *
En&f( select aname and convert (
En&n) select aname and aname )
En&no select aname and aname *
En&s) select aname and "1" )
En&so select aname and "1" *
En&v) select aname and @version )
En&vo select aname and @version *
En(1o select aname ( 1 *
En(f( select aname ( convert (
En(s) select aname ( "1" )
En(so select aname ( "1" *
En(v) select aname ( @version )
En(vo select aname ( @version *
En) select aname )
En)&( select aname ) and (
En)&1 select aname ) and 1
En)&f select aname ) and convert
En)&n select aname ) and aname
En)&s select aname ) and "1"
En)&v select aname ) and @version
En); select aname ) ;
En);( select aname ) ; (
En);E select aname ) ; select
En);T select aname ) ; DROP
En);c select aname ) ;  -- comment
En)UE select aname ) union select
En)c select aname )  -- comment
En)kn select aname ) JOIN aname
En)o( select aname ) * (
En)o1 select aname ) * 1
En)of select aname ) * convert
En)on select aname ) * aname
En)os select aname ) * "1"
En)ov select aname ) * @version
En,(1 select aname , ( 1
En,(f select aname , ( convert
En,(n select aname , ( aname
En,(s select aname , ( "1"
En,(v select aname , ( @version
En,f( select aname , convert (
En1; select aname 1 ;
En1;c select aname 1 ;  -- comment
En1o( select aname 1 * (
En1of select aname 1 * convert
En1os select aname 1 * "1"
En1ov select aname 1 * @version
En;(E select aname ; ( select
EnB(1 select aname group by ( 1
EnB(f select aname group by ( convert
EnB(n select aname group by ( aname
EnB(s select aname group by ( "1"
EnB(v select aname group by ( @version
EnB1) select aname group by 1 )
EnB1o select aname group by 1 *
EnBf( select aname group by convert (
EnBn) select aname group by aname )
EnBno select aname group by aname *
EnBs) select aname group by "1" )
EnBso select aname group by "1" *
EnBv) select aname group by @version )
EnBvo select aname group by @version *
EnU(E select aname union ( select
EnUE( select aname union select (
EnUE1 select aname union select 1
EnUEf select aname union select convert
EnUEk select aname union select JOIN
EnUEn select aname union select aname
EnUEs select aname union select "1"
EnUEv select aname union select @version
Enf() select aname convert ( )
Enf(1 select aname convert ( 1
Enf(f select aname convert ( convert
Enf(n select aname convert ( aname
Enf(s select aname convert ( "1"
Enf(v select aname convert ( @version
Enk(1 select aname JOIN ( 1
Enk(E select aname JOIN ( select
Enk(f select aname JOIN ( convert
Enk(n select aname JOIN ( aname
Enk(s select aname JOIN ( "1"
Enk(v select aname JOIN ( @version
Enk1) select aname JOIN 1 )
Enk1k select aname JOIN 1 JOIN
Enk1o select aname JOIN 1 *
Enkf( select aname JOIN convert (
Enkn) select aname JOIN aname )
Enkn, select aname JOIN aname ,
Enkn; select aname JOIN aname ;
EnknB select aname JOIN aname group by
EnknU select aname JOIN aname union
Enknc select aname JOIN aname  -- comment
Enknk select aname JOIN aname JOIN
Enks) select aname JOIN "1" )
Enksk select aname JOIN "1" JOIN
Enkso select aname JOIN "1" *
Enkv) select aname JOIN @version )
Enkvk select aname JOIN @version JOIN
Enkvo select aname JOIN @version *
Eno(1 select aname * ( 1
Eno(E select aname * ( select
Eno(f select aname * ( convert
Eno(n select aname * ( aname
Eno(s select aname * ( "1"
Eno(v select aname * ( @version
Enof( select aname * convert (
Enos& select aname * "1" and
Enos( select aname * "1" (
Enos) select aname * "1" )
Enos, select aname * "1" ,
Enos1 select aname * "1" 1
Enos; select aname * "1" ;
EnosB select aname * "1" group by
EnosU select aname * "1" union
Enosf select aname * "1" convert
Enosk select aname * "1" JOIN
Enosv select aname * "1" @version
Enov& select aname * @version and
Enov( select aname * @version (
Enov) select aname * @version )
Enov, select aname * @version ,
Enov; select aname * @version ;
EnovB select aname * @version group by
EnovU select aname * @version union
Enovf select aname * @version convert
Enovk select aname * @version JOIN
Enovo select aname * @version *
Enovs select aname * @version "1"
Eok(E select * JOIN ( select
Eoknk select * JOIN aname JOIN
Es&(1 select "1" and ( 1
Es&(E select "1" and ( select
Es&(f select "1" and ( convert
Es&(n select "1" and ( aname
Es&(s select "1" and ( "1"
Es&(v select "1" and ( @version
Es&1) select "1" and 1 )
Es&1o select "1" and 1 *
Es&f( select "1" and convert (
Es&n) select "1" and aname )
Es&no select "1" and aname *
Es&s) select "1" and "1" )
Es&so select "1" and "1" *
Es&v) select "1" and @version )
Es&vo select "1" and @version *
Es) select "1" )
Es)&( select "1" ) and (
Es)&1 select "1" ) and 1
Es)&f select "1" ) and convert
Es)&n select "1" ) and aname
Es)&s select "1" ) and "1"
Es)&v select "1" ) and @version
Es); select "1" ) ;
Es);( select "1" ) ; (
Es);E select "1" ) ; select
Es);T select "1" ) ; DROP
Es);c select "1" ) ;  -- comment
Es)UE select "1" ) union select
Es)c select "1" )  -- comment
Es)kn select "1" ) JOIN aname
Es)o( select "1" ) * (
Es)o1 select "1" ) * 1
Es)of select "1" ) * convert
Es)on select "1" ) * aname
Es)os select "1" ) * "1"
Es)ov select "1" ) * @version
Es,(1 select "1" , ( 1
Es,(f select "1" , ( convert
Es,(n select "1" , ( aname
Es,(s select "1" , ( "1"
Es,(v select "1" , ( @version
Es,f( select "1" , convert (
Es1 select "1" 1
Es1; select "1" 1 ;
Es1;c select "1" 1 ;  -- comment
Es1c select "1" 1  -- comment
Es;(E select "1" ; ( select
EsB(1 select "1" group by ( 1
EsB(f select "1" group by ( convert
EsB(n select "1" group by ( aname
EsB(s select "1" group by ( "1"
EsB(v select "1" group by ( @version
EsB1) select "1" group by 1 )
EsB1o select "1" group by 1 *
EsBf( select "1" group by convert (
EsBn) select "1" group by aname )
EsBno select "1" group by aname *
EsBs) select "1" group by "1" )
EsBso select "1" group by "1" *
EsBv) select "1" group by @version )
EsBvo select "1" group by @version *
EsU(E select "1" union ( select
EsUE( select "1" union select (
EsUE1 select "1" union select 1
EsUEf select "1" union select convert
EsUEk select "1" union select JOIN
EsUEn select "1" union select aname
EsUEs select "1" union select "1"
EsUEv select "1" union select @version
Esf() select "1" convert ( )
Esf(1 select "1" convert ( 1
Esf(f select "1" convert ( convert
Esf(n select "1" convert ( aname
Esf(s select "1" convert ( "1"
Esf(v select "1" convert ( @version
Esk(1 select "1" JOIN ( 1
Esk(E select "1" JOIN ( select
Esk(f select "1" JOIN ( convert
Esk(n select "1" JOIN ( aname
Esk(s select "1" JOIN ( "1"
Esk(v select "1" JOIN ( @version
Esk1) select "1" JOIN 1 )
Esk1k select "1" JOIN 1 JOIN
Esk1o select "1" JOIN 1 *
Eskf( select "1" JOIN convert (
Eskn select "1" JOIN aname
Eskn) select "1" JOIN aname )
Eskn; select "1" JOIN aname ;
EsknU select "1" JOIN aname union
Esknc select "1" JOIN aname  -- comment
Esknk select "1" JOIN aname JOIN
Esks) select "1" JOIN "1" )
Esksk select "1" JOIN "1" JOIN
Eskso select "1" JOIN "1" *
Eskv) select "1" JOIN @version )
Eskvk select "1" JOIN @version JOIN
Eskvo select "1" JOIN @version *
Eso(1 select "1" * ( 1
Eso(E select "1" * ( select
Eso(f select "1" * ( convert
Eso(n select "1" * ( aname
Eso(s select "1" * ( "1"
Eso(v select "1" * ( @version
Eso1& select "1" * 1 and
Eso1( select "1" * 1 (
Eso1) select "1" * 1 )
Eso1, select "1" * 1 ,
Eso1; select "1" * 1 ;
Eso1B select "1" * 1 group by
Eso1U select "1" * 1 union
Eso1f select "1" * 1 convert
Eso1k select "1" * 1 JOIN
Eso1n select "1" * 1 aname
Eso1s select "1" * 1 "1"
Eso1v select "1" * 1 @version
Esof( select "1" * convert (
Eson& select "1" * aname and
Eson( select "1" * aname (
Eson) select "1" * aname )
Eson, select "1" * aname ,
Eson1 select "1" * aname 1
Eson; select "1" * aname ;
EsonB select "1" * aname group by
EsonU select "1" * aname union
Esonf select "1" * aname convert
Esonk select "1" * aname JOIN
Esos& select "1" * "1" and
Esos( select "1" * "1" (
Esos) select "1" * "1" )
Esos, select "1" * "1" ,
Esos1 select "1" * "1" 1
Esos; select "1" * "1" ;
EsosB select "1" * "1" group by
EsosU select "1" * "1" union
Esosf select "1" * "1" convert
Esosk select "1" * "1" JOIN
Esosv select "1" * "1" @version
Esov& select "1" * @version and
Esov( select "1" * @version (
Esov) select "1" * @version )
Esov, select "1" * @version ,
Esov; select "1" * @version ;
EsovB select "1" * @version group by
EsovU select "1" * @version union
Esovf select "1" * @version convert
Esovk select "1" * @version JOIN
Esovo select "1" * @version *
Esovs select "1" * @version "1"
Esv select "1" @version
Esv; select "1" @version ;
Esv;c select "1" @version ;  -- comment
Esvc select "1" @version  -- comment
Esvo( select "1" @version * (
Esvof select "1" @version * convert
Esvos select "1" @version * "1"
Ev&(1 select @version and ( 1
Ev&(E select @version and ( select
Ev&(f select @version and ( convert
Ev&(n select @version and ( aname
Ev&(s select @version and ( "1"
Ev&(v select @version and ( @version
Ev&1) select @version and 1 )
Ev&1o select @version and 1 *
Ev&f( select @version and convert (
Ev&n) select @version and aname )
Ev&no select @version and aname *
Ev&s) select @version and "1" )
Ev&so select @version and "1" *
Ev&v) select @version and @version )
Ev&vo select @version and @version *
Ev) select @version )
Ev)&( select @version ) and (
Ev)&1 select @version ) and 1
Ev)&f select @version ) and convert
Ev)&n select @version ) and aname
Ev)&s select @version ) and "1"
Ev)&v select @version ) and @version
Ev); select @version ) ;
Ev);( select @version ) ; (
Ev);E select @version ) ; select
Ev);T select @version ) ; DROP
Ev);c select @version ) ;  -- comment
Ev)UE select @version ) union select
Ev)c select @version )  -- comment
Ev)kn select @version ) JOIN aname
Ev)o( select @version ) * (
Ev)o1 select @version ) * 1
Ev)of select @version ) * convert
Ev)on select @version ) * aname
Ev)os select @version ) * "1"
Ev)ov select @version ) * @version
Ev,(1 select @version , ( 1
Ev,(f select @version , ( convert
Ev,(n select @version , ( aname
Ev,(s select @version , ( "1"
Ev,(v select @version , ( @version
Ev,f( select @version , convert (
Ev;(E select @version ; ( select
EvB(1 select @version group by ( 1
EvB(f select @version group by ( convert
EvB(n select @version group by ( aname
EvB(s select @version group by ( "1"
EvB(v select @version group by ( @version
EvB1) select @version group by 1 )
EvB1o select @version group by 1 *
EvBf( select @version group by convert (
EvBn) select @version group by aname )
EvBno select @version group by aname *
EvBs) select @version group by "1" )
EvBso select @version group by "1" *
EvBv) select @version group by @version )
EvBvo select @version group by @version *
EvU(E select @version union ( select
EvUE( select @version union select (
EvUE1 select @version union select 1
EvUEf select @version union select convert
EvUEk select @version union select JOIN
EvUEn select @version union select aname
EvUEs select @version union select "1"
EvUEv select @version union select @version
Evf() select @version convert ( )
Evf(1 select @version convert ( 1
Evf(f select @version convert ( convert
Evf(n select @version convert ( aname
Evf(s select @version convert ( "1"
Evf(v select @version convert ( @version
Evk(1 select @version JOIN ( 1
Evk(E select @version JOIN ( select
Evk(f select @version JOIN ( convert
Evk(n select @version JOIN ( aname
Evk(s select @version JOIN ( "1"
Evk(v select @version JOIN ( @version
Evk1) select @version JOIN 1 )
Evk1k select @version JOIN 1 JOIN
Evk1o select @version JOIN 1 *
Evkf( select @version JOIN convert (
Evkn select @version JOIN aname
Evkn) select @version JOIN aname )
Evkn; select @version JOIN aname ;
EvknU select @version JOIN aname union
Evknc select @version JOIN aname  -- comment
Evknk select @version JOIN aname JOIN
Evks) select @version JOIN "1" )
Evksk select @version JOIN "1" JOIN
Evkso select @version JOIN "1" *
Evkv) select @version JOIN @version )
Evkvk select @version JOIN @version JOIN
Evkvo select @version JOIN @version *
Evn select @version aname
Evn)U select @version aname ) union
Evn; select @version aname ;
Evn;c select @version aname ;  -- comment
Evnc select @version aname  -- comment
Evnkn select @version aname JOIN aname
Evno( select @version aname * (
Evnof select @version aname * convert
Evnos select @version aname * "1"
Evnov select @version aname * @version
Evo(1 select @version * ( 1
Evo(E select @version * ( select
Evo(f select @version * ( convert
Evo(n select @version * ( aname
Evo(s select @version * ( "1"
Evo(v select @version * ( @version
Evof( select @version * convert (
Evos& select @version * "1" and
Evos( select @version * "1" (
Evos) select @version * "1" )
Evos, select @version * "1" ,
Evos1 select @version * "1" 1
Evos; select @version * "1" ;
EvosB select @version * "1" group by
EvosU select @version * "1" union
Evosf select @version * "1" convert
Evosk select @version * "1" JOIN
Evosv select @version * "1" @version
Evs select @version "1"
Evs; select @version "1" ;
Evs;c select @version "1" ;  -- comment
Evsc select @version "1"  -- comment
Evso( select @version "1" * (
Evso1 select @version "1" * 1
Evsof select @version "1" * convert
Evson select @version "1" * aname
Evsos select @version "1" * "1"
Evsov select @version "1" * @version
T(1)f DROP ( 1 ) convert
T(1)o DROP ( 1 ) *
T(1f( DROP ( 1 convert (
T(1n) DROP ( 1 aname )
T(1o( DROP ( 1 * (
T(1of DROP ( 1 * convert
T(1os DROP ( 1 * "1"
T(1ov DROP ( 1 * @version
T(1s) DROP ( 1 "1" )
T(1v) DROP ( 1 @version )
T(1vo DROP ( 1 @version *
T(f() DROP ( convert ( )
T(f(1 DROP ( convert ( 1
T(f(f DROP ( convert ( convert
T(f(n DROP ( convert ( aname
T(f(s DROP ( convert ( "1"
T(f(v DROP ( convert ( @version
T(n(1 DROP ( aname ( 1
T(n(f DROP ( aname ( convert
T(n(s DROP ( aname ( "1"
T(n(v DROP ( aname ( @version
T(n)f DROP ( aname ) convert
T(n)o DROP ( aname ) *
T(n1) DROP ( aname 1 )
T(n1o DROP ( aname 1 *
T(nf( DROP ( aname convert (
T(nn) DROP ( aname aname )
T(nno DROP ( aname aname *
T(no( DROP ( aname * (
T(nof DROP ( aname * convert
T(nos DROP ( aname * "1"
T(nov DROP ( aname * @version
T(ns) DROP ( aname "1" )
T(nso DROP ( aname "1" *
T(nv) DROP ( aname @version )
T(nvo DROP ( aname @version *
T(s)f DROP ( "1" ) convert
T(s)o DROP ( "1" ) *
T(s1) DROP ( "1" 1 )
T(sf( DROP ( "1" convert (
T(sn) DROP ( "1" aname )
T(sno DROP ( "1" aname *
T(so( DROP ( "1" * (
T(so1 DROP ( "1" * 1
T(sof DROP ( "1" * convert
T(son DROP ( "1" * aname
T(sos DROP ( "1" * "1"
T(sov DROP ( "1" * @version
T(sv) DROP ( "1" @version )
T(svo DROP ( "1" @version *
T(v)f DROP ( @version ) convert
T(v)o DROP ( @version ) *
T(vf( DROP ( @version convert (
T(vo( DROP ( @version * (
T(vof DROP ( @version * convert
T(vos DROP ( @version * "1"
T(vs) DROP ( @version "1" )
T(vso DROP ( @version "1" *
T(vv) DROP ( @version @version )
T1f(1 DROP 1 convert ( 1
T1f(f DROP 1 convert ( convert
T1f(n DROP 1 convert ( aname
T1f(s DROP 1 convert ( "1"
T1f(v DROP 1 convert ( @version
T1o(1 DROP 1 * ( 1
T1o(f DROP 1 * ( convert
T1o(n DROP 1 * ( aname
T1o(s DROP 1 * ( "1"
T1o(v DROP 1 * ( @version
T1of( DROP 1 * convert (
T1osf DROP 1 * "1" convert
T1ovf DROP 1 * @version convert
T1ovo DROP 1 * @version *
Tf()f DROP convert ( ) convert
Tf()o DROP convert ( ) *
Tf(1) DROP convert ( 1 )
Tf(1o DROP convert ( 1 *
Tf(f( DROP convert ( convert (
Tf(n) DROP convert ( aname )
Tf(no DROP convert ( aname *
Tf(s) DROP convert ( "1" )
Tf(so DROP convert ( "1" *
Tf(v) DROP convert ( @version )
Tf(vo DROP convert ( @version *
Tn(1) DROP aname ( 1 )
Tn(1o DROP aname ( 1 *
Tn(f( DROP aname ( convert (
Tn(s) DROP aname ( "1" )
Tn(so DROP aname ( "1" *
Tn(v) DROP aname ( @version )
Tn(vo DROP aname ( @version *
Tn1; DROP aname 1 ;
Tn1;c DROP aname 1 ;  -- comment
Tn1o( DROP aname 1 * (
Tn1of DROP aname 1 * convert
Tn1os DROP aname 1 * "1"
Tn1ov DROP aname 1 * @version
Tnf() DROP aname convert ( )
Tnf(1 DROP aname convert ( 1
Tnf(f DROP aname convert ( convert
Tnf(n DROP aname convert ( aname
Tnf(s DROP aname convert ( "1"
Tnf(v DROP aname convert ( @version
Tnn; DROP aname aname ;
Tnn;c DROP aname aname ;  -- comment
Tnno( DROP aname aname * (
Tnnof DROP aname aname * convert
Tnnos DROP aname aname * "1"
Tnnov DROP aname aname * @version
Tno(1 DROP aname * ( 1
Tno(f DROP aname * ( convert
Tno(n DROP aname * ( aname
Tno(s DROP aname * ( "1"
Tno(v DROP aname * ( @version
Tnof( DROP aname * convert (
Tnosf DROP aname * "1" convert
Tnovf DROP aname * @version convert
Tnovo DROP aname * @version *
Tns; DROP aname "1" ;
Tns;c DROP aname "1" ;  -- comment
Tnso( DROP aname "1" * (
Tnso1 DROP aname "1" * 1
Tnsof DROP aname "1" * convert
Tnson DROP aname "1" * aname
Tnsos DROP aname "1" * "1"
Tnsov DROP aname "1" * @version
Tnv; DROP aname @version ;
Tnv;c DROP aname @version ;  -- comment
Tnvo( DROP aname @version * (
Tnvof DROP aname @version * convert
Tnvos DROP aname @version * "1"
Tsf(1 DROP "1" convert ( 1
Tsf(f DROP "1" convert ( convert
Tsf(n DROP "1" convert ( aname
Tsf(s DROP "1" convert ( "1"
Tsf(v DROP "1" convert ( @version
Tso(1 DROP "1" * ( 1
Tso(f DROP "1" * ( convert
Tso(n DROP "1" * ( aname
Tso(s DROP "1" * ( "1"
Tso(v DROP "1" * ( @version
Tso1f DROP "1" * 1 convert
Tsof( DROP "1" * convert (
Tsonf DROP "1" * aname convert
Tsosf DROP "1" * "1" convert
Tsovf DROP "1" * @version convert
Tsovo DROP "1" * @version *
Tvf(1 DROP @version convert ( 1
Tvf(f DROP @version convert ( convert
Tvf(n DROP @version convert ( aname
Tvf(s DROP @version convert ( "1"
Tvf(v DROP @version convert ( @version
Tvo(1 DROP @version * ( 1
Tvo(f DROP @version * ( convert
Tvo(n DROP @version * ( aname
Tvo(s DROP @version * ( "1"
Tvo(v DROP @version * ( @version
Tvof( DROP @version * convert (
Tvosf DROP @version * "1" convert
U(E(1 union ( select ( 1
U(E(f union ( select ( convert
U(E(k union ( select ( JOIN
U(E(n union ( select ( aname
U(E(s union ( select ( "1"
U(E(v union ( select ( @version
U(E1) union ( select 1 )
U(E1o union ( select 1 *
U(Ef( union ( select convert (
U(Ek( union ( select JOIN (
U(Ek1 union ( select JOIN 1
U(Ekf union ( select JOIN convert
U(Ekn union ( select JOIN aname
U(Eko union ( select JOIN *
U(Eks union ( select JOIN "1"
U(Ekv union ( select JOIN @version
U(En) union ( select aname )
U(Enk union ( select aname JOIN
U(Eno union ( select aname *
U(Eok union ( select * JOIN
U(Es) union ( select "1" )
U(Eso union ( select "1" *
U(Ev) union ( select @version )
U(Evo union ( select @version *
UE(1) union select ( 1 )
UE(1, union select ( 1 ,
UE(1o union select ( 1 *
UE(f( union select ( convert (
UE(n) union select ( aname )
UE(n, union select ( aname ,
UE(no union select ( aname *
UE(s) union select ( "1" )
UE(s, union select ( "1" ,
UE(so union select ( "1" *
UE(v) union select ( @version )
UE(v, union select ( @version ,
UE(vo union select ( @version *
UE1 union select 1
UE1,( union select 1 , (
UE1,f union select 1 , convert
UE1; union select 1 ;
UE1;c union select 1 ;  -- comment
UE1c union select 1  -- comment
UE1k( union select 1 JOIN (
UE1k1 union select 1 JOIN 1
UE1kf union select 1 JOIN convert
UE1kn union select 1 JOIN aname
UE1ks union select 1 JOIN "1"
UE1kv union select 1 JOIN @version
UE1o( union select 1 * (
UE1of union select 1 * convert
UE1os union select 1 * "1"
UE1ov union select 1 * @version
UEf() union select convert ( )
UEf(1 union select convert ( 1
UEf(f union select convert ( convert
UEf(n union select convert ( aname
UEf(s union select convert ( "1"
UEf(v union select convert ( @version
UEk(1 union select JOIN ( 1
UEk(f union select JOIN ( convert
UEk(n union select JOIN ( aname
UEk(s union select JOIN ( "1"
UEk(v union select JOIN ( @version
UEk1 union select JOIN 1
UEk1, union select JOIN 1 ,
UEk1; union select JOIN 1 ;
UEk1c union select JOIN 1  -- comment
UEk1k union select JOIN 1 JOIN
UEk1o union select JOIN 1 *
UEkf( union select JOIN convert (
UEkn union select JOIN aname
UEkn( union select JOIN aname (
UEkn, union select JOIN aname ,
UEkn; union select JOIN aname ;
UEknc union select JOIN aname  -- comment
UEknk union select JOIN aname JOIN
UEks union select JOIN "1"
UEks, union select JOIN "1" ,
UEks; union select JOIN "1" ;
UEksc union select JOIN "1"  -- comment
UEksk union select JOIN "1" JOIN
UEkso union select JOIN "1" *
UEkv union select JOIN @version
UEkv, union select JOIN @version ,
UEkv; union select JOIN @version ;
UEkvc union select JOIN @version  -- comment
UEkvk union select JOIN @version JOIN
UEkvo union select JOIN @version *
UEn() union select aname ( )
UEn,( union select aname , (
UEn,f union select aname , convert
UEn; union select aname ;
UEn;c union select aname ;  -- comment
UEnc union select aname  -- comment
UEnk( union select aname JOIN (
UEnk1 union select aname JOIN 1
UEnkf union select aname JOIN convert
UEnkn union select aname JOIN aname
UEnks union select aname JOIN "1"
UEnkv union select aname JOIN @version
UEno( union select aname * (
UEnof union select aname * convert
UEnos union select aname * "1"
UEnov union select aname * @version
UEs union select "1"
UEs,( union select "1" , (
UEs,f union select "1" , convert
UEs; union select "1" ;
UEs;c union select "1" ;  -- comment
UEsc union select "1"  -- comment
UEsk( union select "1" JOIN (
UEsk1 union select "1" JOIN 1
UEskf union select "1" JOIN convert
UEskn union select "1" JOIN aname
UEsks union select "1" JOIN "1"
UEskv union select "1" JOIN @version
UEso( union select "1" * (
UEso1 union select "1" * 1
UEsof union select "1" * convert
UEson union select "1" * aname
UEsos union select "1" * "1"
UEsov union select "1" * @version
UEv union select @version
UEv,( union select @version , (
UEv,f union select @version , convert
UEv; union select @version ;
UEv;c union select @version ;  -- comment
UEvc union select @version  -- comment
UEvk( union select @version JOIN (
UEvk1 union select @version JOIN 1
UEvkf union select @version JOIN convert
UEvkn union select @version JOIN aname
UEvks union select @version JOIN "1"
UEvkv union select @version JOIN @version
UEvo( union select @version * (
UEvof union select @version * convert
UEvos union select @version * "1"
Uf(1o union convert ( 1 *
Uf(f( union convert ( convert (
Uf(no union convert ( aname *
Uf(so union convert ( "1" *
Uf(vo union convert ( @version *
X /* /* nested comment */ */
f()&( convert ( ) and (
f()&1 convert ( ) and 1
f()&E convert ( ) and select
f()&f convert ( ) and convert
f()&k convert ( ) and JOIN
f()&n convert ( ) and aname
f()&s convert ( ) and "1"
f()&v convert ( ) and @version
f(),( convert ( ) , (
f(),1 convert ( ) , 1
f(),f convert ( ) , convert
f(),n convert ( ) , aname
f(),s convert ( ) , "1"
f(),v convert ( ) , @version
f()1( convert ( ) 1 (
f()1U convert ( ) 1 union
f()1f convert ( ) 1 convert
f()1n convert ( ) 1 aname
f()1o convert ( ) 1 *
f()1s convert ( ) 1 "1"
f()1v convert ( ) 1 @version
f();E convert ( ) ; select
f();T convert ( ) ; DROP
f();n convert ( ) ; aname
f()A( convert ( ) COLLATE (
f()Af convert ( ) COLLATE convert
f()As convert ( ) COLLATE "1"
f()At convert ( ) COLLATE binary
f()Av convert ( ) COLLATE @version
f()B( convert ( ) group by (
f()B1 convert ( ) group by 1
f()BE convert ( ) group by select
f()Bf convert ( ) group by convert
f()Bn convert ( ) group by aname
f()Bs convert ( ) group by "1"
f()Bv convert ( ) group by @version
f()E( convert ( ) select (
f()E1 convert ( ) select 1
f()EU convert ( ) select union
f()Ef convert ( ) select convert
f()Ek convert ( ) select JOIN
f()En convert ( ) select aname
f()Eo convert ( ) select *
f()Es convert ( ) select "1"
f()Ev convert ( ) select @version
f()T( convert ( ) DROP (
f()T1 convert ( ) DROP 1
f()TE convert ( ) DROP select
f()TT convert ( ) DROP DROP
f()Tf convert ( ) DROP convert
f()Tn convert ( ) DROP aname
f()Ts convert ( ) DROP "1"
f()Tv convert ( ) DROP @version
f()U convert ( ) union
f()U( convert ( ) union (
f()U1 convert ( ) union 1
f()U; convert ( ) union ;
f()UE convert ( ) union select
f()UT convert ( ) union DROP
f()Uc convert ( ) union  -- comment
f()Uf convert ( ) union convert
f()Uk convert ( ) union JOIN
f()Uo convert ( ) union *
f()Us convert ( ) union "1"
f()Uv convert ( ) union @version
f()c convert ( )  -- comment
f()f( convert ( ) convert (
f()k( convert ( ) JOIN (
f()k) convert ( ) JOIN )
f()k1 convert ( ) JOIN 1
f()kU convert ( ) JOIN union
f()kf convert ( ) JOIN convert
f()kn convert ( ) JOIN aname
f()ks convert ( ) JOIN "1"
f()kv convert ( ) JOIN @version
f()n& convert ( ) aname and
f()n( convert ( ) aname (
f()n) convert ( ) aname )
f()n, convert ( ) aname ,
f()n1 convert ( ) aname 1
f()nE convert ( ) aname select
f()nU convert ( ) aname union
f()nf convert ( ) aname convert
f()no convert ( ) aname *
f()o( convert ( ) * (
f()o1 convert ( ) * 1
f()oU convert ( ) * union
f()of convert ( ) * convert
f()ok convert ( ) * JOIN
f()on convert ( ) * aname
f()os convert ( ) * "1"
f()ov convert ( ) * @version
f()s( convert ( ) "1" (
f()s1 convert ( ) "1" 1
f()sU convert ( ) "1" union
f()sf convert ( ) "1" convert
f()so convert ( ) "1" *
f()sv convert ( ) "1" @version
f()v( convert ( ) @version (
f()vU convert ( ) @version union
f()vf convert ( ) @version convert
f()vo convert ( ) @version *
f()vs convert ( ) @version "1"
f(1&( convert ( 1 and (
f(1&1 convert ( 1 and 1
f(1&f convert ( 1 and convert
f(1&n convert ( 1 and aname
f(1&s convert ( 1 and "1"
f(1&v convert ( 1 and @version
f(1) convert ( 1 )
f(1)& convert ( 1 ) and
f(1), convert ( 1 ) ,
f(1)1 convert ( 1 ) 1
f(1); convert ( 1 ) ;
f(1)A convert ( 1 ) COLLATE
f(1)B convert ( 1 ) group by
f(1)E convert ( 1 ) select
f(1)T convert ( 1 ) DROP
f(1)U convert ( 1 ) union
f(1)c convert ( 1 )  -- comment
f(1)f convert ( 1 ) convert
f(1)k convert ( 1 ) JOIN
f(1)n convert ( 1 ) aname
f(1)o convert ( 1 ) *
f(1)s convert ( 1 ) "1"
f(1)v convert ( 1 ) @version
f(1,( convert ( 1 , (
f(1,f convert ( 1 , convert
f(1o( convert ( 1 * (
f(1of convert ( 1 * convert
f(1os convert ( 1 * "1"
f(1ov convert ( 1 * @version
f(E(1 convert ( select ( 1
f(E(E convert ( select ( select
f(E(f convert ( select ( convert
f(E(n convert ( select ( aname
f(E(s convert ( select ( "1"
f(E(v convert ( select ( @version
f(E1& convert ( select 1 and
f(E1) convert ( select 1 )
f(E1k convert ( select 1 JOIN
f(E1o convert ( select 1 *
f(Ef( convert ( select convert (
f(Ek( convert ( select JOIN (
f(Ek1 convert ( select JOIN 1
f(Ekf convert ( select JOIN convert
f(Ekn convert ( select JOIN aname
f(Eko convert ( select JOIN *
f(Eks convert ( select JOIN "1"
f(Ekv convert ( select JOIN @version
f(En& convert ( select aname and
f(En) convert ( select aname )
f(Enk convert ( select aname JOIN
f(Eno convert ( select aname *
f(Eok convert ( select * JOIN
f(Es& convert ( select "1" and
f(Es) convert ( select "1" )
f(Esk convert ( select "1" JOIN
f(Eso convert ( select "1" *
f(Ev& convert ( select @version and
f(Ev) convert ( select @version )
f(Evk convert ( select @version JOIN
f(Evo convert ( select @version *
f(f() convert ( convert ( )
f(f(1 convert ( convert ( 1
f(f(E convert ( convert ( select
f(f(f convert ( convert ( convert
f(f(n convert ( convert ( aname
f(f(s convert ( convert ( "1"
f(f(v convert ( convert ( @version
f(k() convert ( JOIN ( )
f(k,( convert ( JOIN , (
f(k,f convert ( JOIN , convert
f(n&( convert ( aname and (
f(n&1 convert ( aname and 1
f(n&f convert ( aname and convert
f(n&n convert ( aname and aname
f(n&s convert ( aname and "1"
f(n&v convert ( aname and @version
f(n) convert ( aname )
f(n)& convert ( aname ) and
f(n), convert ( aname ) ,
f(n)1 convert ( aname ) 1
f(n); convert ( aname ) ;
f(n)A convert ( aname ) COLLATE
f(n)B convert ( aname ) group by
f(n)E convert ( aname ) select
f(n)T convert ( aname ) DROP
f(n)U convert ( aname ) union
f(n)c convert ( aname )  -- comment
f(n)f convert ( aname ) convert
f(n)k convert ( aname ) JOIN
f(n)n convert ( aname ) aname
f(n)o convert ( aname ) *
f(n)s convert ( aname ) "1"
f(n)v convert ( aname ) @version
f(n,( convert ( aname , (
f(n,f convert ( aname , convert
f(no( convert ( aname * (
f(nof convert ( aname * convert
f(nos convert ( aname * "1"
f(nov convert ( aname * @version
f(s&( convert ( "1" and (
f(s&1 convert ( "1" and 1
f(s&f convert ( "1" and convert
f(s&n convert ( "1" and aname
f(s&s convert ( "1" and "1"
f(s&v convert ( "1" and @version
f(s) convert ( "1" )
f(s)& convert ( "1" ) and
f(s), convert ( "1" ) ,
f(s)1 convert ( "1" ) 1
f(s); convert ( "1" ) ;
f(s)A convert ( "1" ) COLLATE
f(s)B convert ( "1" ) group by
f(s)E convert ( "1" ) select
f(s)T convert ( "1" ) DROP
f(s)U convert ( "1" ) union
f(s)c convert ( "1" )  -- comment
f(s)f convert ( "1" ) convert
f(s)k convert ( "1" ) JOIN
f(s)n convert ( "1" ) aname
f(s)o convert ( "1" ) *
f(s)s convert ( "1" ) "1"
f(s)v convert ( "1" ) @version
f(s,( convert ( "1" , (
f(s,f convert ( "1" , convert
f(so( convert ( "1" * (
f(so1 convert ( "1" * 1
f(sof convert ( "1" * convert
f(son convert ( "1" * aname
f(sos convert ( "1" * "1"
f(sov convert ( "1" * @version
f(t,( convert ( binary , (
f(t,f convert ( binary , convert
f(v&( convert ( @version and (
f(v&1 convert ( @version and 1
f(v&f convert ( @version and convert
f(v&n convert ( @version and aname
f(v&s convert ( @version and "1"
f(v&v convert ( @version and @version
f(v) convert ( @version )
f(v)& convert ( @version ) and
f(v), convert ( @version ) ,
f(v)1 convert ( @version ) 1
f(v); convert ( @version ) ;
f(v)A convert ( @version ) COLLATE
f(v)B convert ( @version ) group by
f(v)E convert ( @version ) select
f(v)T convert ( @version ) DROP
f(v)U convert ( @version ) union
f(v)c convert ( @version )  -- comment
f(v)f convert ( @version ) convert
f(v)k convert ( @version ) JOIN
f(v)n convert ( @version ) aname
f(v)o convert ( @version ) *
f(v)s convert ( @version ) "1"
f(v)v convert ( @version ) @version
f(v,( convert ( @version , (
f(v,f convert ( @version , convert
f(vo( convert ( @version * (
f(vof convert ( @version * convert
f(vos convert ( @version * "1"
k(1), JOIN ( 1 ) ,
k(1)A JOIN ( 1 ) COLLATE
k(1)k JOIN ( 1 ) JOIN
k(1)o JOIN ( 1 ) *
k(1o( JOIN ( 1 * (
k(1of JOIN ( 1 * convert
k(1os JOIN ( 1 * "1"
k(1ov JOIN ( 1 * @version
k(f() JOIN ( convert ( )
k(f(1 JOIN ( convert ( 1
k(f(f JOIN ( convert ( convert
k(f(n JOIN ( convert ( aname
k(f(s JOIN ( convert ( "1"
k(f(v JOIN ( convert ( @version
k(n), JOIN ( aname ) ,
k(n)A JOIN ( aname ) COLLATE
k(n)k JOIN ( aname ) JOIN
k(n)o JOIN ( aname ) *
k(no( JOIN ( aname * (
k(nof JOIN ( aname * convert
k(nos JOIN ( aname * "1"
k(nov JOIN ( aname * @version
k(s), JOIN ( "1" ) ,
k(s)A JOIN ( "1" ) COLLATE
k(s)k JOIN ( "1" ) JOIN
k(s)o JOIN ( "1" ) *
k(so( JOIN ( "1" * (
k(so1 JOIN ( "1" * 1
k(sof JOIN ( "1" * convert
k(son JOIN ( "1" * aname
k(sos JOIN ( "1" * "1"
k(sov JOIN ( "1" * @version
k(v), JOIN ( @version ) ,
k(v)A JOIN ( @version ) COLLATE
k(v)k JOIN ( @version ) JOIN
k(v)o JOIN ( @version ) *
k(vo( JOIN ( @version * (
k(vof JOIN ( @version * convert
k(vos JOIN ( @version * "1"
k1,(1 JOIN 1 , ( 1
k1,(f JOIN 1 , ( convert
k1,(n JOIN 1 , ( aname
k1,(s JOIN 1 , ( "1"
k1,(v JOIN 1 , ( @version
k1,f( JOIN 1 , convert (
k1A(f JOIN 1 COLLATE ( convert
k1A(n JOIN 1 COLLATE ( aname
k1A(s JOIN 1 COLLATE ( "1"
k1A(v JOIN 1 COLLATE ( @version
k1Af( JOIN 1 COLLATE convert (
k1Aso JOIN 1 COLLATE "1" *
k1Avo JOIN 1 COLLATE @version *
k1k(1 JOIN 1 JOIN ( 1
k1k(f JOIN 1 JOIN ( convert
k1k(n JOIN 1 JOIN ( aname
k1k(s JOIN 1 JOIN ( "1"
k1k(v JOIN 1 JOIN ( @version
k1k1U JOIN 1 JOIN 1 union
k1k1o JOIN 1 JOIN 1 *
k1kf( JOIN 1 JOIN convert (
k1knU JOIN 1 JOIN aname union
k1ksU JOIN 1 JOIN "1" union
k1kso JOIN 1 JOIN "1" *
k1kvU JOIN 1 JOIN @version union
k1kvo JOIN 1 JOIN @version *
k1o(1 JOIN 1 * ( 1
k1o(f JOIN 1 * ( convert
k1o(n JOIN 1 * ( aname
k1o(s JOIN 1 * ( "1"
k1o(v JOIN 1 * ( @version
k1of( JOIN 1 * convert (
k1os( JOIN 1 * "1" (
k1os, JOIN 1 * "1" ,
k1os1 JOIN 1 * "1" 1
k1osA JOIN 1 * "1" COLLATE
k1osf JOIN 1 * "1" convert
k1osk JOIN 1 * "1" JOIN
k1osv JOIN 1 * "1" @version
k1ov( JOIN 1 * @version (
k1ov, JOIN 1 * @version ,
k1ovA JOIN 1 * @version COLLATE
k1ovf JOIN 1 * @version convert
k1ovk JOIN 1 * @version JOIN
k1ovo JOIN 1 * @version *
k1ovs JOIN 1 * @version "1"
kf(), JOIN convert ( ) ,
kf()A JOIN convert ( ) COLLATE
kf()k JOIN convert ( ) JOIN
kf()o JOIN convert ( ) *
kf(1) JOIN convert ( 1 )
kf(1o JOIN convert ( 1 *
kf(f( JOIN convert ( convert (
kf(n) JOIN convert ( aname )
kf(no JOIN convert ( aname *
kf(s) JOIN convert ( "1" )
kf(so JOIN convert ( "1" *
kf(v) JOIN convert ( @version )
kf(vo JOIN convert ( @version *
kn,(1 JOIN aname , ( 1
kn,(f JOIN aname , ( convert
kn,(n JOIN aname , ( aname
kn,(s JOIN aname , ( "1"
kn,(v JOIN aname , ( @version
kn,f( JOIN aname , convert (
knA(f JOIN aname COLLATE ( convert
knA(n JOIN aname COLLATE ( aname
knA(s JOIN aname COLLATE ( "1"
knA(v JOIN aname COLLATE ( @version
knAf( JOIN aname COLLATE convert (
knAso JOIN aname COLLATE "1" *
knAvo JOIN aname COLLATE @version *
knk(1 JOIN aname JOIN ( 1
knk(f JOIN aname JOIN ( convert
knk(n JOIN aname JOIN ( aname
knk(s JOIN aname JOIN ( "1"
knk(v JOIN aname JOIN ( @version
knk1U JOIN aname JOIN 1 union
knk1o JOIN aname JOIN 1 *
knkf( JOIN aname JOIN convert (
knknU JOIN aname JOIN aname union
knksU JOIN aname JOIN "1" union
knkso JOIN aname JOIN "1" *
knkvU JOIN aname JOIN @version union
knkvo JOIN aname JOIN @version *
ks,(1 JOIN "1" , ( 1
ks,(f JOIN "1" , ( convert
ks,(n JOIN "1" , ( aname
ks,(s JOIN "1" , ( "1"
ks,(v JOIN "1" , ( @version
ks,f( JOIN "1" , convert (
ksA(f JOIN "1" COLLATE ( convert
ksA(n JOIN "1" COLLATE ( aname
ksA(s JOIN "1" COLLATE ( "1"
ksA(v JOIN "1" COLLATE ( @version
ksAf( JOIN "1" COLLATE convert (
ksAso JOIN "1" COLLATE "1" *
ksAvo JOIN "1" COLLATE @version *
ksk(1 JOIN "1" JOIN ( 1
ksk(f JOIN "1" JOIN ( convert
ksk(n JOIN "1" JOIN ( aname
ksk(s JOIN "1" JOIN ( "1"
ksk(v JOIN "1" JOIN ( @version
ksk1U JOIN "1" JOIN 1 union
ksk1o JOIN "1" JOIN 1 *
kskf( JOIN "1" JOIN convert (
ksknU JOIN "1" JOIN aname union
ksksU JOIN "1" JOIN "1" union
kskso JOIN "1" JOIN "1" *
kskvU JOIN "1" JOIN @version union
kskvo JOIN "1" JOIN @version *
kso(1 JOIN "1" * ( 1
kso(f JOIN "1" * ( convert
kso(n JOIN "1" * ( aname
kso(s JOIN "1" * ( "1"
kso(v JOIN "1" * ( @version
kso1( JOIN "1" * 1 (
kso1, JOIN "1" * 1 ,
kso1A JOIN "1" * 1 COLLATE
kso1f JOIN "1" * 1 convert
kso1k JOIN "1" * 1 JOIN
kso1n JOIN "1" * 1 aname
kso1s JOIN "1" * 1 "1"
kso1v JOIN "1" * 1 @version
ksof( JOIN "1" * convert (
kson( JOIN "1" * aname (
kson, JOIN "1" * aname ,
kson1 JOIN "1" * aname 1
ksonA JOIN "1" * aname COLLATE
ksonf JOIN "1" * aname convert
ksonk JOIN "1" * aname JOIN
ksos( JOIN "1" * "1" (
ksos, JOIN "1" * "1" ,
ksos1 JOIN "1" * "1" 1
ksosA JOIN "1" * "1" COLLATE
ksosf JOIN "1" * "1" convert
ksosk JOIN "1" * "1" JOIN
ksosv JOIN "1" * "1" @version
ksov( JOIN "1" * @version (
ksov, JOIN "1" * @version ,
ksovA JOIN "1" * @version COLLATE
ksovf JOIN "1" * @version convert
ksovk JOIN "1" * @version JOIN
ksovo JOIN "1" * @version *
ksovs JOIN "1" * @version "1"
kv,(1 JOIN @version , ( 1
kv,(f JOIN @version , ( convert
kv,(n JOIN @version , ( aname
kv,(s JOIN @version , ( "1"
kv,(v JOIN @version , ( @version
kv,f( JOIN @version , convert (
kvA(f JOIN @version COLLATE ( convert
kvA(n JOIN @version COLLATE ( aname
kvA(s JOIN @version COLLATE ( "1"
kvA(v JOIN @version COLLATE ( @version
kvAf( JOIN @version COLLATE convert (
kvAso JOIN @version COLLATE "1" *
kvAvo JOIN @version COLLATE @version *
kvk(1 JOIN @version JOIN ( 1
kvk(f JOIN @version JOIN ( convert
kvk(n JOIN @version JOIN ( aname
kvk(s JOIN @version JOIN ( "1"
kvk(v JOIN @version JOIN ( @version
kvk1U JOIN @version JOIN 1 union
kvk1o JOIN @version JOIN 1 *
kvkf( JOIN @version JOIN convert (
kvknU JOIN @version JOIN aname union
kvksU JOIN @version JOIN "1" union
kvkso JOIN @version JOIN "1" *
kvkvU JOIN @version JOIN @version union
kvkvo JOIN @version JOIN @version *
kvo(1 JOIN @version * ( 1
kvo(f JOIN @version * ( convert
kvo(n JOIN @version * ( aname
kvo(s JOIN @version * ( "1"
kvo(v JOIN @version * ( @version
kvof( JOIN @version * convert (
kvos( JOIN @version * "1" (
kvos, JOIN @version * "1" ,
kvos1 JOIN @version * "1" 1
kvosA JOIN @version * "1" COLLATE
kvosf JOIN @version * "1" convert
kvosk JOIN @version * "1" JOIN
kvosv JOIN @version * "1" @version
n&(1& aname and ( 1 and
n&(1) aname and ( 1 )
n&(1, aname and ( 1 ,
n&(1o aname and ( 1 *
n&(E( aname and ( select (
n&(E1 aname and ( select 1
n&(Ef aname and ( select convert
n&(Ek aname and ( select JOIN
n&(En aname and ( select aname
n&(Eo aname and ( select *
n&(Es aname and ( select "1"
n&(Ev aname and ( select @version
n&(f( aname and ( convert (
n&(n& aname and ( aname and
n&(n) aname and ( aname )
n&(n, aname and ( aname ,
n&(no aname and ( aname *
n&(s& aname and ( "1" and
n&(s) aname and ( "1" )
n&(s, aname and ( "1" ,
n&(so aname and ( "1" *
n&(v& aname and ( @version and
n&(v) aname and ( @version )
n&(v, aname and ( @version ,
n&(vo aname and ( @version *
n&1 aname and 1
n&1&( aname and 1 and (
n&1&1 aname and 1 and 1
n&1&f aname and 1 and convert
n&1&n aname and 1 and aname
n&1&s aname and 1 and "1"
n&1&v aname and 1 and @version
n&1)& aname and 1 ) and
n&1)U aname and 1 ) union
n&1)c aname and 1 )  -- comment
n&1)o aname and 1 ) *
n&1; aname and 1 ;
n&1;E aname and 1 ; select
n&1;T aname and 1 ; DROP
n&1;c aname and 1 ;  -- comment
n&1B( aname and 1 group by (
n&1B1 aname and 1 group by 1
n&1Bf aname and 1 group by convert
n&1Bn aname and 1 group by aname
n&1Bs aname and 1 group by "1"
n&1Bv aname and 1 group by @version
n&1Ek aname and 1 select JOIN
n&1En aname and 1 select aname
n&1Tn aname and 1 DROP aname
n&1U aname and 1 union
n&1U( aname and 1 union (
n&1U; aname and 1 union ;
n&1UE aname and 1 union select
n&1Uc aname and 1 union  -- comment
n&1c aname and 1  -- comment
n&1f( aname and 1 convert (
n&1k( aname and 1 JOIN (
n&1k1 aname and 1 JOIN 1
n&1kf aname and 1 JOIN convert
n&1kn aname and 1 JOIN aname
n&1ks aname and 1 JOIN "1"
n&1kv aname and 1 JOIN @version
n&1o( aname and 1 * (
n&1of aname and 1 * convert
n&1os aname and 1 * "1"
n&1ov aname and 1 * @version
n&E(1 aname and select ( 1
n&E(f aname and select ( convert
n&E(n aname and select ( aname
n&E(o aname and select ( *
n&E(s aname and select ( "1"
n&E(v aname and select ( @version
n&E1 aname and select 1
n&E1; aname and select 1 ;
n&E1c aname and select 1  -- comment
n&E1k aname and select 1 JOIN
n&E1o aname and select 1 *
n&Ef( aname and select convert (
n&Ek( aname and select JOIN (
n&Ek1 aname and select JOIN 1
n&Ekf aname and select JOIN convert
n&Ekn aname and select JOIN aname
n&Eks aname and select JOIN "1"
n&Ekv aname and select JOIN @version
n&En; aname and select aname ;
n&Enc aname and select aname  -- comment
n&Enk aname and select aname JOIN
n&Eno aname and select aname *
n&Es aname and select "1"
n&Es; aname and select "1" ;
n&Esc aname and select "1"  -- comment
n&Esk aname and select "1" JOIN
n&Eso aname and select "1" *
n&Ev aname and select @version
n&Ev; aname and select @version ;
n&Evc aname and select @version  -- comment
n&Evk aname and select @version JOIN
n&Evo aname and select @version *
n&f() aname and convert ( )
n&f(1 aname and convert ( 1
n&f(E aname and convert ( select
n&f(f aname and convert ( convert
n&f(n aname and convert ( aname
n&f(s aname and convert ( "1"
n&f(v aname and convert ( @version
n&k&( aname and JOIN and (
n&k&1 aname and JOIN and 1
n&k&f aname and JOIN and convert
n&k&n aname and JOIN and aname
n&k&s aname and JOIN and "1"
n&k&v aname and JOIN and @version
n&k(1 aname and JOIN ( 1
n&k(f aname and JOIN ( convert
n&k(n aname and JOIN ( aname
n&k(s aname and JOIN ( "1"
n&k(v aname and JOIN ( @version
n&k1o aname and JOIN 1 *
n&kc aname and JOIN  -- comment
n&kf( aname and JOIN convert (
n&knk aname and JOIN aname JOIN
n&ko( aname and JOIN * (
n&ko1 aname and JOIN * 1
n&kof aname and JOIN * convert
n&kok aname and JOIN * JOIN
n&kon aname and JOIN * aname
n&kos aname and JOIN * "1"
n&kov aname and JOIN * @version
n&kso aname and JOIN "1" *
n&kvo aname and JOIN @version *
n&n&( aname and aname and (
n&n&1 aname and aname and 1
n&n&f aname and aname and convert
n&n&s aname and aname and "1"
n&n&v aname and aname and @version
n&n)& aname and aname ) and
n&n)U aname and aname ) union
n&n)c aname and aname )  -- comment
n&n)o aname and aname ) *
n&n;E aname and aname ; select
n&n;T aname and aname ; DROP
n&n;c aname and aname ;  -- comment
n&nB( aname and aname group by (
n&nB1 aname and aname group by 1
n&nBf aname and aname group by convert
n&nBs aname and aname group by "1"
n&nBv aname and aname group by @version
n&nU aname and aname union
n&nU( aname and aname union (
n&nU; aname and aname union ;
n&nUE aname and aname union select
n&nUc aname and aname union  -- comment
n&nf( aname and aname convert (
n&nk( aname and aname JOIN (
n&nk1 aname and aname JOIN 1
n&nkf aname and aname JOIN convert
n&nks aname and aname JOIN "1"
n&nkv aname and aname JOIN @version
n&no( aname and aname * (
n&nof aname and aname * convert
n&nos aname and aname * "1"
n&nov aname and aname * @version
n&s&( aname and "1" and (
n&s&1 aname and "1" and 1
n&s&f aname and "1" and convert
n&s&n aname and "1" and aname
n&s&s aname and "1" and "1"
n&s&v aname and "1" and @version
n&s)& aname and "1" ) and
n&s)U aname and "1" ) union
n&s)c aname and "1" )  -- comment
n&s)o aname and "1" ) *
n&s1 aname and "1" 1
n&s1; aname and "1" 1 ;
n&s1c aname and "1" 1  -- comment
n&s; aname and "1" ;
n&s;E aname and "1" ; select
n&s;T aname and "1" ; DROP
n&s;c aname and "1" ;  -- comment
n&sB( aname and "1" group by (
n&sB1 aname and "1" group by 1
n&sBf aname and "1" group by convert
n&sBn aname and "1" group by aname
n&sBs aname and "1" group by "1"
n&sBv aname and "1" group by @version
n&sEk aname and "1" select JOIN
n&sEn aname and "1" select aname
n&sTn aname and "1" DROP aname
n&sU aname and "1" union
n&sU( aname and "1" union (
n&sU; aname and "1" union ;
n&sUE aname and "1" union select
n&sUc aname and "1" union  -- comment
n&sc aname and "1"  -- comment
n&sf( aname and "1" convert (
n&sk( aname and "1" JOIN (
n&sk1 aname and "1" JOIN 1
n&skf aname and "1" JOIN convert
n&skn aname and "1" JOIN aname
n&sks aname and "1" JOIN "1"
n&skv aname and "1" JOIN @version
n&so( aname and "1" * (
n&so1 aname and "1" * 1
n&sof aname and "1" * convert
n&son aname and "1" * aname
n&sos aname and "1" * "1"
n&sov aname and "1" * @version
n&sv aname and "1" @version
n&sv; aname and "1" @version ;
n&svc aname and "1" @version  -- comment
n&svo aname and "1" @version *
n&v aname and @version
n&v&( aname and @version and (
n&v&1 aname and @version and 1
n&v&f aname and @version and convert
n&v&n aname and @version and aname
n&v&s aname and @version and "1"
n&v&v aname and @version and @version
n&v)& aname and @version ) and
n&v)U aname and @version ) union
n&v)c aname and @version )  -- comment
n&v)o aname and @version ) *
n&v; aname and @version ;
n&v;E aname and @version ; select
n&v;T aname and @version ; DROP
n&v;c aname and @version ;  -- comment
n&vB( aname and @version group by (
n&vB1 aname and @version group by 1
n&vBf aname and @version group by convert
n&vBn aname and @version group by aname
n&vBs aname and @version group by "1"
n&vBv aname and @version group by @version
n&vEk aname and @version select JOIN
n&vEn aname and @version select aname
n&vTn aname and @version DROP aname
n&vU aname and @version union
n&vU( aname and @version union (
n&vU; aname and @version union ;
n&vUE aname and @version union select
n&vUc aname and @version union  -- comment
n&vc aname and @version  -- comment
n&vf( aname and @version convert (
n&vk( aname and @version JOIN (
n&vk1 aname and @version JOIN 1
n&vkf aname and @version JOIN convert
n&vkn aname and @version JOIN aname
n&vks aname and @version JOIN "1"
n&vkv aname and @version JOIN @version
n&vo( aname and @version * (
n&vof aname and @version * convert
n&vos aname and @version * "1"
n&vs aname and @version "1"
n&vs; aname and @version "1" ;
n&vsc aname and @version "1"  -- comment
n&vso aname and @version "1" *
n)&(1 aname ) and ( 1
n)&(E aname ) and ( select
n)&(f aname ) and ( convert
n)&(n aname ) and ( aname
n)&(s aname ) and ( "1"
n)&(v aname ) and ( @version
n)&1 aname ) and 1
n)&1& aname ) and 1 and
n)&1) aname ) and 1 )
n)&1; aname ) and 1 ;
n)&1B aname ) and 1 group by
n)&1U aname ) and 1 union
n)&1c aname ) and 1  -- comment
n)&1f aname ) and 1 convert
n)&1o aname ) and 1 *
n)&f( aname ) and convert (
n)&n aname ) and aname
n)&n& aname ) and aname and
n)&n) aname ) and aname )
n)&n; aname ) and aname ;
n)&nB aname ) and aname group by
n)&nU aname ) and aname union
n)&nc aname ) and aname  -- comment
n)&nf aname ) and aname convert
n)&no aname ) and aname *
n)&s aname ) and "1"
n)&s& aname ) and "1" and
n)&s) aname ) and "1" )
n)&s; aname ) and "1" ;
n)&sB aname ) and "1" group by
n)&sU aname ) and "1" union
n)&sc aname ) and "1"  -- comment
n)&sf aname ) and "1" convert
n)&so aname ) and "1" *
n)&v aname ) and @version
n)&v& aname ) and @version and
n)&v) aname ) and @version )
n)&v; aname ) and @version ;
n)&vB aname ) and @version group by
n)&vU aname ) and @version union
n)&vc aname ) and @version  -- comment
n)&vf aname ) and @version convert
n)&vo aname ) and @version *
n),(1 aname ) , ( 1
n),(f aname ) , ( convert
n),(n aname ) , ( aname
n),(s aname ) , ( "1"
n),(v aname ) , ( @version
n);E( aname ) ; select (
n);E1 aname ) ; select 1
n);Ef aname ) ; select convert
n);Ek aname ) ; select JOIN
n);En aname ) ; select aname
n);Eo aname ) ; select *
n);Es aname ) ; select "1"
n);Ev aname ) ; select @version
n);T( aname ) ; DROP (
n);T1 aname ) ; DROP 1
n);Tf aname ) ; DROP convert
n);Tk aname ) ; DROP JOIN
n);Tn aname ) ; DROP aname
n);To aname ) ; DROP *
n);Ts aname ) ; DROP "1"
n);Tv aname ) ; DROP @version
n)B(1 aname ) group by ( 1
n)B(f aname ) group by ( convert
n)B(n aname ) group by ( aname
n)B(s aname ) group by ( "1"
n)B(v aname ) group by ( @version
n)B1 aname ) group by 1
n)B1& aname ) group by 1 and
n)B1; aname ) group by 1 ;
n)B1U aname ) group by 1 union
n)B1c aname ) group by 1  -- comment
n)B1k aname ) group by 1 JOIN
n)B1n aname ) group by 1 aname
n)B1o aname ) group by 1 *
n)Bf( aname ) group by convert (
n)Bn aname ) group by aname
n)Bn& aname ) group by aname and
n)Bn; aname ) group by aname ;
n)BnU aname ) group by aname union
n)Bnc aname ) group by aname  -- comment
n)Bnk aname ) group by aname JOIN
n)Bno aname ) group by aname *
n)Bs aname ) group by "1"
n)Bs& aname ) group by "1" and
n)Bs; aname ) group by "1" ;
n)BsU aname ) group by "1" union
n)Bsc aname ) group by "1"  -- comment
n)Bsk aname ) group by "1" JOIN
n)Bso aname ) group by "1" *
n)Bv aname ) group by @version
n)Bv& aname ) group by @version and
n)Bv; aname ) group by @version ;
n)BvU aname ) group by @version union
n)Bvc aname ) group by @version  -- comment
n)Bvk aname ) group by @version JOIN
n)Bvo aname ) group by @version *
n)E(1 aname ) select ( 1
n)E(f aname ) select ( convert
n)E(n aname ) select ( aname
n)E(s aname ) select ( "1"
n)E(v aname ) select ( @version
n)E1c aname ) select 1  -- comment
n)E1o aname ) select 1 *
n)Ef( aname ) select convert (
n)Ek( aname ) select JOIN (
n)Ek1 aname ) select JOIN 1
n)Ekf aname ) select JOIN convert
n)Ekn aname ) select JOIN aname
n)Eks aname ) select JOIN "1"
n)Ekv aname ) select JOIN @version
n)Enc aname ) select aname  -- comment
n)Eno aname ) select aname *
n)Esc aname ) select "1"  -- comment
n)Eso aname ) select "1" *
n)Evc aname ) select @version  -- comment
n)Evo aname ) select @version *
n)U(E aname ) union ( select
n)UE( aname ) union select (
n)UE1 aname ) union select 1
n)UEf aname ) union select convert
n)UEk aname ) union select JOIN
n)UEn aname ) union select aname
n)UEs aname ) union select "1"
n)UEv aname ) union select @version
n)f(f aname ) convert ( convert
n)k(1 aname ) JOIN ( 1
n)k(f aname ) JOIN ( convert
n)k(n aname ) JOIN ( aname
n)k(s aname ) JOIN ( "1"
n)k(v aname ) JOIN ( @version
n)k1& aname ) JOIN 1 and
n)k1; aname ) JOIN 1 ;
n)k1B aname ) JOIN 1 group by
n)k1E aname ) JOIN 1 select
n)k1U aname ) JOIN 1 union
n)k1o aname ) JOIN 1 *
n)kB( aname ) JOIN group by (
n)kB1 aname ) JOIN group by 1
n)kBf aname ) JOIN group by convert
n)kBn aname ) JOIN group by aname
n)kBs aname ) JOIN group by "1"
n)kBv aname ) JOIN group by @version
n)kUE aname ) JOIN union select
n)kf( aname ) JOIN convert (
n)kn& aname ) JOIN aname and
n)kn; aname ) JOIN aname ;
n)knB aname ) JOIN aname group by
n)knE aname ) JOIN aname select
n)knU aname ) JOIN aname union
n)knc aname ) JOIN aname  -- comment
n)knk aname ) JOIN aname JOIN
n)ks& aname ) JOIN "1" and
n)ks; aname ) JOIN "1" ;
n)ksB aname ) JOIN "1" group by
n)ksE aname ) JOIN "1" select
n)ksU aname ) JOIN "1" union
n)kso aname ) JOIN "1" *
n)kv& aname ) JOIN @version and
n)kv; aname ) JOIN @version ;
n)kvB aname ) JOIN @version group by
n)kvE aname ) JOIN @version select
n)kvU aname ) JOIN @version union
n)kvo aname ) JOIN @version *
n)o(1 aname ) * ( 1
n)o(E aname ) * ( select
n)o(f aname ) * ( convert
n)o(n aname ) * ( aname
n)o(s aname ) * ( "1"
n)o(v aname ) * ( @version
n)o1& aname ) * 1 and
n)o1) aname ) * 1 )
n)o1; aname ) * 1 ;
n)o1B aname ) * 1 group by
n)o1U aname ) * 1 union
n)o1c aname ) * 1  -- comment
n)o1k aname ) * 1 JOIN
n)of( aname ) * convert (
n)on& aname ) * aname and
n)on) aname ) * aname )
n)on; aname ) * aname ;
n)onB aname ) * aname group by
n)onU aname ) * aname union
n)onc aname ) * aname  -- comment
n)onk aname ) * aname JOIN
n)os aname ) * "1"
n)os& aname ) * "1" and
n)os) aname ) * "1" )
n)os; aname ) * "1" ;
n)osB aname ) * "1" group by
n)osU aname ) * "1" union
n)osc aname ) * "1"  -- comment
n)osk aname ) * "1" JOIN
n)ov aname ) * @version
n)ov& aname ) * @version and
n)ov) aname ) * @version )
n)ov; aname ) * @version ;
n)ovB aname ) * @version group by
n)ovU aname ) * @version union
n)ovc aname ) * @version  -- comment
n)ovk aname ) * @version JOIN
n)ovo aname ) * @version *
n,(1) aname , ( 1 )
n,(1o aname , ( 1 *
n,(E( aname , ( select (
n,(E1 aname , ( select 1
n,(Ef aname , ( select convert
n,(Ek aname , ( select JOIN
n,(En aname , ( select aname
n,(Es aname , ( select "1"
n,(Ev aname , ( select @version
n,(f( aname , ( convert (
n,(no aname , ( aname *
n,(s) aname , ( "1" )
n,(so aname , ( "1" *
n,(v) aname , ( @version )
n,(vo aname , ( @version *
n,f() aname , convert ( )
n,f(1 aname , convert ( 1
n,f(f aname , convert ( convert
n,f(n aname , convert ( aname
n,f(s aname , convert ( "1"
n,f(v aname , convert ( @version
n1UE aname 1 union select
n1UE; aname 1 union select ;
n1UEc aname 1 union select  -- comment
n1UEk aname 1 union select JOIN
n1o(1 aname 1 * ( 1
n1o(f aname 1 * ( convert
n1o(n aname 1 * ( aname
n1o(s aname 1 * ( "1"
n1o(v aname 1 * ( @version
n1of( aname 1 * convert (
n1os( aname 1 * "1" (
n1os1 aname 1 * "1" 1
n1osU aname 1 * "1" union
n1osf aname 1 * "1" convert
n1osv aname 1 * "1" @version
n1ov( aname 1 * @version (
n1ovU aname 1 * @version union
n1ovf aname 1 * @version convert
n1ovo aname 1 * @version *
n1ovs aname 1 * @version "1"
n1s; aname 1 "1" ;
n1s;c aname 1 "1" ;  -- comment
n1sc aname 1 "1"  -- comment
n1v; aname 1 @version ;
n1v;c aname 1 @version ;  -- comment
n1vc aname 1 @version  -- comment
n1vo( aname 1 @version * (
n1vof aname 1 @version * convert
n1vos aname 1 @version * "1"
n;E(1 aname ; select ( 1
n;E(E aname ; select ( select
n;E(f aname ; select ( convert
n;E(n aname ; select ( aname
n;E(s aname ; select ( "1"
n;E(v aname ; select ( @version
n;E1, aname ; select 1 ,
n;E1; aname ; select 1 ;
n;E1T aname ; select 1 DROP
n;E1c aname ; select 1  -- comment
n;E1k aname ; select 1 JOIN
n;E1o aname ; select 1 *
n;Ef( aname ; select convert (
n;Ek( aname ; select JOIN (
n;Ek1 aname ; select JOIN 1
n;Ekf aname ; select JOIN convert
n;Ekn aname ; select JOIN aname
n;Eko aname ; select JOIN *
n;Eks aname ; select JOIN "1"
n;Ekv aname ; select JOIN @version
n;En, aname ; select aname ,
n;En; aname ; select aname ;
n;EnE aname ; select aname select
n;EnT aname ; select aname DROP
n;Enc aname ; select aname  -- comment
n;Enk aname ; select aname JOIN
n;Eno aname ; select aname *
n;Es, aname ; select "1" ,
n;Es; aname ; select "1" ;
n;EsT aname ; select "1" DROP
n;Esc aname ; select "1"  -- comment
n;Esk aname ; select "1" JOIN
n;Eso aname ; select "1" *
n;Ev, aname ; select @version ,
n;Ev; aname ; select @version ;
n;EvT aname ; select @version DROP
n;Evc aname ; select @version  -- comment
n;Evk aname ; select @version JOIN
n;Evo aname ; select @version *
n;T(1 aname ; DROP ( 1
n;T(E aname ; DROP ( select
n;T(c aname ; DROP (  -- comment
n;T(f aname ; DROP ( convert
n;T(n aname ; DROP ( aname
n;T(s aname ; DROP ( "1"
n;T(v aname ; DROP ( @version
n;T1( aname ; DROP 1 (
n;T1, aname ; DROP 1 ,
n;T1; aname ; DROP 1 ;
n;T1T aname ; DROP 1 DROP
n;T1c aname ; DROP 1  -- comment
n;T1f aname ; DROP 1 convert
n;T1k aname ; DROP 1 JOIN
n;T1o aname ; DROP 1 *
n;T; aname ; DROP ;
n;T;c aname ; DROP ;  -- comment
n;TTn aname ; DROP DROP aname
n;Tf( aname ; DROP convert (
n;Tk( aname ; DROP JOIN (
n;Tk1 aname ; DROP JOIN 1
n;Tkf aname ; DROP JOIN convert
n;Tkk aname ; DROP JOIN JOIN
n;Tko aname ; DROP JOIN *
n;Tks aname ; DROP JOIN "1"
n;Tkv aname ; DROP JOIN @version
n;Tn( aname ; DROP aname (
n;Tn, aname ; DROP aname ,
n;Tn1 aname ; DROP aname 1
n;Tn; aname ; DROP aname ;
n;TnE aname ; DROP aname select
n;TnT aname ; DROP aname DROP
n;Tnc aname ; DROP aname  -- comment
n;Tnf aname ; DROP aname convert
n;Tnk aname ; DROP aname JOIN
n;Tnn aname ; DROP aname aname
n;Tno aname ; DROP aname *
n;Tns aname ; DROP aname "1"
n;Tnv aname ; DROP aname @version
n;To( aname ; DROP * (
n;Ts( aname ; DROP "1" (
n;Ts, aname ; DROP "1" ,
n;Ts; aname ; DROP "1" ;
n;TsT aname ; DROP "1" DROP
n;Tsc aname ; DROP "1"  -- comment
n;Tsf aname ; DROP "1" convert
n;Tsk aname ; DROP "1" JOIN
n;Tso aname ; DROP "1" *
n;Tv( aname ; DROP @version (
n;Tv, aname ; DROP @version ,
n;Tv; aname ; DROP @version ;
n;TvT aname ; DROP @version DROP
n;Tvc aname ; DROP @version  -- comment
n;Tvf aname ; DROP @version convert
n;Tvk aname ; DROP @version JOIN
n;Tvo aname ; DROP @version *
n;n:T aname ; aname : DROP
nA(f( aname COLLATE ( convert (
nA(n) aname COLLATE ( aname )
nA(no aname COLLATE ( aname *
nA(s) aname COLLATE ( "1" )
nA(so aname COLLATE ( "1" *
nA(v) aname COLLATE ( @version )
nA(vo aname COLLATE ( @version *
nAf() aname COLLATE convert ( )
nAf(1 aname COLLATE convert ( 1
nAf(f aname COLLATE convert ( convert
nAf(n aname COLLATE convert ( aname
nAf(s aname COLLATE convert ( "1"
nAf(v aname COLLATE convert ( @version
nAsUE aname COLLATE "1" union select
nAso( aname COLLATE "1" * (
nAso1 aname COLLATE "1" * 1
nAsof aname COLLATE "1" * convert
nAson aname COLLATE "1" * aname
nAsos aname COLLATE "1" * "1"
nAsov aname COLLATE "1" * @version
nAtUE aname COLLATE binary union select
nAto( aname COLLATE binary * (
nAto1 aname COLLATE binary * 1
nAtof aname COLLATE binary * convert
nAton aname COLLATE binary * aname
nAtos aname COLLATE binary * "1"
nAtov aname COLLATE binary * @version
nAvUE aname COLLATE @version union select
nAvo( aname COLLATE @version * (
nAvof aname COLLATE @version * convert
nAvos aname COLLATE @version * "1"
nB(1& aname group by ( 1 and
nB(1) aname group by ( 1 )
nB(1o aname group by ( 1 *
nB(f( aname group by ( convert (
nB(n& aname group by ( aname and
nB(no aname group by ( aname *
nB(s& aname group by ( "1" and
nB(s) aname group by ( "1" )
nB(so aname group by ( "1" *
nB(v& aname group by ( @version and
nB(v) aname group by ( @version )
nB(vo aname group by ( @version *
nB1 aname group by 1
nB1&( aname group by 1 and (
nB1&1 aname group by 1 and 1
nB1&f aname group by 1 and convert
nB1&n aname group by 1 and aname
nB1&s aname group by 1 and "1"
nB1&v aname group by 1 and @version
nB1,( aname group by 1 , (
nB1,f aname group by 1 , convert
nB1; aname group by 1 ;
nB1;c aname group by 1 ;  -- comment
nB1B( aname group by 1 group by (
nB1B1 aname group by 1 group by 1
nB1Bf aname group by 1 group by convert
nB1Bn aname group by 1 group by aname
nB1Bs aname group by 1 group by "1"
nB1Bv aname group by 1 group by @version
nB1U( aname group by 1 union (
nB1UE aname group by 1 union select
nB1c aname group by 1  -- comment
nB1k( aname group by 1 JOIN (
nB1k1 aname group by 1 JOIN 1
nB1kf aname group by 1 JOIN convert
nB1kn aname group by 1 JOIN aname
nB1ks aname group by 1 JOIN "1"
nB1kv aname group by 1 JOIN @version
nB1o( aname group by 1 * (
nB1of aname group by 1 * convert
nB1os aname group by 1 * "1"
nB1ov aname group by 1 * @version
nBE(1 aname group by select ( 1
nBE(f aname group by select ( convert
nBE(n aname group by select ( aname
nBE(s aname group by select ( "1"
nBE(v aname group by select ( @version
nBEk( aname group by select JOIN (
nBf() aname group by convert ( )
nBf(1 aname group by convert ( 1
nBf(f aname group by convert ( convert
nBf(n aname group by convert ( aname
nBf(s aname group by convert ( "1"
nBf(v aname group by convert ( @version
nBn&( aname group by aname and (
nBn&1 aname group by aname and 1
nBn&f aname group by aname and convert
nBn&n aname group by aname and aname
nBn&s aname group by aname and "1"
nBn&v aname group by aname and @version
nBn,( aname group by aname , (
nBn,f aname group by aname , convert
nBn; aname group by aname ;
nBn;c aname group by aname ;  -- comment
nBnB( aname group by aname group by (
nBnB1 aname group by aname group by 1
nBnBf aname group by aname group by convert
nBnBn aname group by aname group by aname
nBnBs aname group by aname group by "1"
nBnBv aname group by aname group by @version
nBnU( aname group by aname union (
nBnUE aname group by aname union select
nBnc aname group by aname  -- comment
nBnk( aname group by aname JOIN (
nBnk1 aname group by aname JOIN 1
nBnkf aname group by aname JOIN convert
nBnkn aname group by aname JOIN aname
nBnks aname group by aname JOIN "1"
nBnkv aname group by aname JOIN @version
nBno( aname group by aname * (
nBnof aname group by aname * convert
nBnos aname group by aname * "1"
nBnov aname group by aname * @version
nBs aname group by "1"
nBs&( aname group by "1" and (
nBs&1 aname group by "1" and 1
nBs&f aname group by "1" and convert
nBs&n aname group by "1" and aname
nBs&s aname group by "1" and "1"
nBs&v aname group by "1" and @version
nBs,( aname group by "1" , (
nBs,f aname group by "1" , convert
nBs; aname group by "1" ;
nBs;c aname group by "1" ;  -- comment
nBsB( aname group by "1" group by (
nBsB1 aname group by "1" group by 1
nBsBf aname group by "1" group by convert
nBsBn aname group by "1" group by aname
nBsBs aname group by "1" group by "1"
nBsBv aname group by "1" group by @version
nBsU( aname group by "1" union (
nBsUE aname group by "1" union select
nBsc aname group by "1"  -- comment
nBsk( aname group by "1" JOIN (
nBsk1 aname group by "1" JOIN 1
nBskf aname group by "1" JOIN convert
nBskn aname group by "1" JOIN aname
nBsks aname group by "1" JOIN "1"
nBskv aname group by "1" JOIN @version
nBso( aname group by "1" * (
nBso1 aname group by "1" * 1
nBsof aname group by "1" * convert
nBson aname group by "1" * aname
nBsos aname group by "1" * "1"
nBsov aname group by "1" * @version
nBv aname group by @version
nBv&( aname group by @version and (
nBv&1 aname group by @version and 1
nBv&f aname group by @version and convert
nBv&n aname group by @version and aname
nBv&s aname group by @version and "1"
nBv&v aname group by @version and @version
nBv,( aname group by @version , (
nBv,f aname group by @version , convert
nBv; aname group by @version ;
nBv;c aname group by @version ;  -- comment
nBvB( aname group by @version group by (
nBvB1 aname group by @version group by 1
nBvBf aname group by @version group by convert
nBvBn aname group by @version group by aname
nBvBs aname group by @version group by "1"
nBvBv aname group by @version group by @version
nBvU( aname group by @version union (
nBvUE aname group by @version union select
nBvc aname group by @version  -- comment
nBvk( aname group by @version JOIN (
nBvk1 aname group by @version JOIN 1
nBvkf aname group by @version JOIN convert
nBvkn aname group by @version JOIN aname
nBvks aname group by @version JOIN "1"
nBvkv aname group by @version JOIN @version
nBvo( aname group by @version * (
nBvof aname group by @version * convert
nBvos aname group by @version * "1"
nE(1) aname select ( 1 )
nE(1o aname select ( 1 *
nE(f( aname select ( convert (
nE(n) aname select ( aname )
nE(no aname select ( aname *
nE(s) aname select ( "1" )
nE(so aname select ( "1" *
nE(v) aname select ( @version )
nE(vo aname select ( @version *
nE1;T aname select 1 ; DROP
nE1T( aname select 1 DROP (
nE1T1 aname select 1 DROP 1
nE1Tf aname select 1 DROP convert
nE1Tn aname select 1 DROP aname
nE1Ts aname select 1 DROP "1"
nE1Tv aname select 1 DROP @version
nE1UE aname select 1 union select
nE1c aname select 1  -- comment
nE1o( aname select 1 * (
nE1of aname select 1 * convert
nE1os aname select 1 * "1"
nE1ov aname select 1 * @version
nEU(1 aname select union ( 1
nEU(f aname select union ( convert
nEU(n aname select union ( aname
nEU(s aname select union ( "1"
nEU(v aname select union ( @version
nEU1, aname select union 1 ,
nEU1c aname select union 1  -- comment
nEU1o aname select union 1 *
nEUEf aname select union select convert
nEUEk aname select union select JOIN
nEUf( aname select union convert (
nEUs, aname select union "1" ,
nEUsc aname select union "1"  -- comment
nEUso aname select union "1" *
nEUv, aname select union @version ,
nEUvc aname select union @version  -- comment
nEUvo aname select union @version *
nEf() aname select convert ( )
nEf(1 aname select convert ( 1
nEf(f aname select convert ( convert
nEf(n aname select convert ( aname
nEf(s aname select convert ( "1"
nEf(v aname select convert ( @version
nEn;T aname select aname ; DROP
nEnT( aname select aname DROP (
nEnT1 aname select aname DROP 1
nEnTf aname select aname DROP convert
nEnTn aname select aname DROP aname
nEnTs aname select aname DROP "1"
nEnTv aname select aname DROP @version
nEnUE aname select aname union select
nEno( aname select aname * (
nEnof aname select aname * convert
nEnos aname select aname * "1"
nEnov aname select aname * @version
nEokn aname select * JOIN aname
nEs;T aname select "1" ; DROP
nEsT( aname select "1" DROP (
nEsT1 aname select "1" DROP 1
nEsTf aname select "1" DROP convert
nEsTn aname select "1" DROP aname
nEsTs aname select "1" DROP "1"
nEsTv aname select "1" DROP @version
nEsUE aname select "1" union select
nEsc aname select "1"  -- comment
nEso( aname select "1" * (
nEso1 aname select "1" * 1
nEsof aname select "1" * convert
nEson aname select "1" * aname
nEsos aname select "1" * "1"
nEsov aname select "1" * @version
nEv;T aname select @version ; DROP
nEvT( aname select @version DROP (
nEvT1 aname select @version DROP 1
nEvTf aname select @version DROP convert
nEvTn aname select @version DROP aname
nEvTs aname select @version DROP "1"
nEvTv aname select @version DROP @version
nEvUE aname select @version union select
nEvc aname select @version  -- comment
nEvo( aname select @version * (
nEvof aname select @version * convert
nEvos aname select @version * "1"
nT(1) aname DROP ( 1 )
nT(1o aname DROP ( 1 *
nT(f( aname DROP ( convert (
nT(n) aname DROP ( aname )
nT(no aname DROP ( aname *
nT(s) aname DROP ( "1" )
nT(so aname DROP ( "1" *
nT(v) aname DROP ( @version )
nT(vo aname DROP ( @version *
nT1(f aname DROP 1 ( convert
nT1o( aname DROP 1 * (
nT1of aname DROP 1 * convert
nT1os aname DROP 1 * "1"
nT1ov aname DROP 1 * @version
nTE(1 aname DROP select ( 1
nTE(f aname DROP select ( convert
nTE(n aname DROP select ( aname
nTE(s aname DROP select ( "1"
nTE(v aname DROP select ( @version
nTE1n aname DROP select 1 aname
nTE1o aname DROP select 1 *
nTEf( aname DROP select convert (
nTEk( aname DROP select JOIN (
nTEk1 aname DROP select JOIN 1
nTEkf aname DROP select JOIN convert
nTEkn aname DROP select JOIN aname
nTEks aname DROP select JOIN "1"
nTEkv aname DROP select JOIN @version
nTEnn aname DROP select aname aname
nTEno aname DROP select aname *
nTEsn aname DROP select "1" aname
nTEso aname DROP select "1" *
nTEvn aname DROP select @version aname
nTEvo aname DROP select @version *
nTTnE aname DROP DROP aname select
nTTnT aname DROP DROP aname DROP
nTTnk aname DROP DROP aname JOIN
nTTnn aname DROP DROP aname aname
nTf() aname DROP convert ( )
nTf(1 aname DROP convert ( 1
nTf(f aname DROP convert ( convert
nTf(n aname DROP convert ( aname
nTf(s aname DROP convert ( "1"
nTf(v aname DROP convert ( @version
nTn(1 aname DROP aname ( 1
nTn(f aname DROP aname ( convert
nTn(s aname DROP aname ( "1"
nTn(v aname DROP aname ( @version
nTn1c aname DROP aname 1  -- comment
nTn1o aname DROP aname 1 *
nTn;E aname DROP aname ; select
nTn;T aname DROP aname ; DROP
nTn;n aname DROP aname ; aname
nTnE( aname DROP aname select (
nTnE1 aname DROP aname select 1
nTnEf aname DROP aname select convert
nTnEn aname DROP aname select aname
nTnEs aname DROP aname select "1"
nTnEv aname DROP aname select @version
nTnT( aname DROP aname DROP (
nTnT1 aname DROP aname DROP 1
nTnTf aname DROP aname DROP convert
nTnTn aname DROP aname DROP aname
nTnTs aname DROP aname DROP "1"
nTnTv aname DROP aname DROP @version
nTnf( aname DROP aname convert (
nTnkn aname DROP aname JOIN aname
nTnn: aname DROP aname aname :
nTnnc aname DROP aname aname  -- comment
nTnno aname DROP aname aname *
nTno( aname DROP aname * (
nTnof aname DROP aname * convert
nTnos aname DROP aname * "1"
nTnov aname DROP aname * @version
nTnsc aname DROP aname "1"  -- comment
nTnso aname DROP aname "1" *
nTnvc aname DROP aname @version  -- comment
nTnvo aname DROP aname @version *
nTs(f aname DROP "1" ( convert
nTso( aname DROP "1" * (
nTso1 aname DROP "1" * 1
nTsof aname DROP "1" * convert
nTson aname DROP "1" * aname
nTsos aname DROP "1" * "1"
nTsov aname DROP "1" * @version
nTv(1 aname DROP @version ( 1
nTv(f aname DROP @version ( convert
nTvo( aname DROP @version * (
nTvof aname DROP @version * convert
nTvos aname DROP @version * "1"
nU(1) aname union ( 1 )
nU(1o aname union ( 1 *
nU(E( aname union ( select (
nU(E1 aname union ( select 1
nU(Ef aname union ( select convert
nU(Ek aname union ( select JOIN
nU(En aname union ( select aname
nU(Es aname union ( select "1"
nU(Ev aname union ( select @version
nU(f( aname union ( convert (
nU(n) aname union ( aname )
nU(no aname union ( aname *
nU(s) aname union ( "1" )
nU(so aname union ( "1" *
nU(v) aname union ( @version )
nU(vo aname union ( @version *
nU1,( aname union 1 , (
nU1,f aname union 1 , convert
nU1c aname union 1  -- comment
nU1o( aname union 1 * (
nU1of aname union 1 * convert
nU1os aname union 1 * "1"
nU1ov aname union 1 * @version
nU; aname union ;
nU;c aname union ;  -- comment
nUE aname union select
nUE(1 aname union select ( 1
nUE(E aname union select ( select
nUE(f aname union select ( convert
nUE(n aname union select ( aname
nUE(o aname union select ( *
nUE(s aname union select ( "1"
nUE(v aname union select ( @version
nUE1 aname union select 1
nUE1& aname union select 1 and
nUE1( aname union select 1 (
nUE1) aname union select 1 )
nUE1, aname union select 1 ,
nUE1; aname union select 1 ;
nUE1B aname union select 1 group by
nUE1U aname union select 1 union
nUE1c aname union select 1  -- comment
nUE1f aname union select 1 convert
nUE1k aname union select 1 JOIN
nUE1n aname union select 1 aname
nUE1o aname union select 1 *
nUE1s aname union select 1 "1"
nUE1v aname union select 1 @version
nUE; aname union select ;
nUE;c aname union select ;  -- comment
nUEc aname union select  -- comment
nUEf aname union select convert
nUEf( aname union select convert (
nUEf, aname union select convert ,
nUEf; aname union select convert ;
nUEfc aname union select convert  -- comment
nUEk aname union select JOIN
nUEk( aname union select JOIN (
nUEk1 aname union select JOIN 1
nUEk; aname union select JOIN ;
nUEkc aname union select JOIN  -- comment
nUEkf aname union select JOIN convert
nUEkn aname union select JOIN aname
nUEko aname union select JOIN *
nUEks aname union select JOIN "1"
nUEkv aname union select JOIN @version
nUEn aname union select aname
nUEn& aname union select aname and
nUEn( aname union select aname (
nUEn) aname union select aname )
nUEn, aname union select aname ,
nUEn1 aname union select aname 1
nUEn; aname union select aname ;
nUEnB aname union select aname group by
nUEnU aname union select aname union
nUEnc aname union select aname  -- comment
nUEnf aname union select aname convert
nUEnk aname union select aname JOIN
nUEno aname union select aname *
nUEns aname union select aname "1"
nUEok aname union select * JOIN
nUEon aname union select * aname
nUEs aname union select "1"
nUEs& aname union select "1" and
nUEs( aname union select "1" (
nUEs) aname union select "1" )
nUEs, aname union select "1" ,
nUEs1 aname union select "1" 1
nUEs; aname union select "1" ;
nUEsB aname union select "1" group by
nUEsU aname union select "1" union
nUEsc aname union select "1"  -- comment
nUEsf aname union select "1" convert
nUEsk aname union select "1" JOIN
nUEso aname union select "1" *
nUEsv aname union select "1" @version
nUEv aname union select @version
nUEv& aname union select @version and
nUEv( aname union select @version (
nUEv) aname union select @version )
nUEv, aname union select @version ,
nUEv; aname union select @version ;
nUEvB aname union select @version group by
nUEvU aname union select @version union
nUEvc aname union select @version  -- comment
nUEvf aname union select @version convert
nUEvk aname union select @version JOIN
nUEvn aname union select @version aname
nUEvo aname union select @version *
nUEvs aname union select @version "1"
nUTn( aname union DROP aname (
nUTn1 aname union DROP aname 1
nUTnf aname union DROP aname convert
nUTnn aname union DROP aname aname
nUTns aname union DROP aname "1"
nUTnv aname union DROP aname @version
nUc aname union  -- comment
nUf() aname union convert ( )
nUf(1 aname union convert ( 1
nUf(f aname union convert ( convert
nUf(n aname union convert ( aname
nUf(s aname union convert ( "1"
nUf(v aname union convert ( @version
nUk(E aname union JOIN ( select
nUo(E aname union * ( select
nUon( aname union * aname (
nUon1 aname union * aname 1
nUonf aname union * aname convert
nUons aname union * aname "1"
nUs,( aname union "1" , (
nUs,f aname union "1" , convert
nUsc aname union "1"  -- comment
nUso( aname union "1" * (
nUso1 aname union "1" * 1
nUsof aname union "1" * convert
nUson aname union "1" * aname
nUsos aname union "1" * "1"
nUsov aname union "1" * @version
nUv,( aname union @version , (
nUv,f aname union @version , convert
nUvc aname union @version  -- comment
nUvo( aname union @version * (
nUvof aname union @version * convert
nUvos aname union @version * "1"
nc aname  -- comment
nf()1 aname convert ( ) 1
nf()U aname convert ( ) union
nf()f aname convert ( ) convert
nf()k aname convert ( ) JOIN
nf()n aname convert ( ) aname
nf()o aname convert ( ) *
nf()s aname convert ( ) "1"
nf()v aname convert ( ) @version
nf(1) aname convert ( 1 )
nf(1o aname convert ( 1 *
nf(E( aname convert ( select (
nf(E1 aname convert ( select 1
nf(Ef aname convert ( select convert
nf(Ek aname convert ( select JOIN
nf(En aname convert ( select aname
nf(Es aname convert ( select "1"
nf(Ev aname convert ( select @version
nf(f( aname convert ( convert (
nf(n, aname convert ( aname ,
nf(no aname convert ( aname *
nf(s) aname convert ( "1" )
nf(so aname convert ( "1" *
nf(v) aname convert ( @version )
nf(vo aname convert ( @version *
nk(1) aname JOIN ( 1 )
nk(1o aname JOIN ( 1 *
nk(f( aname JOIN ( convert (
nk(no aname JOIN ( aname *
nk(s) aname JOIN ( "1" )
nk(so aname JOIN ( "1" *
nk(v) aname JOIN ( @version )
nk(vo aname JOIN ( @version *
nk)&( aname JOIN ) and (
nk)&1 aname JOIN ) and 1
nk)&f aname JOIN ) and convert
nk)&n aname JOIN ) and aname
nk)&s aname JOIN ) and "1"
nk)&v aname JOIN ) and @version
nk);E aname JOIN ) ; select
nk);T aname JOIN ) ; DROP
nk)B( aname JOIN ) group by (
nk)B1 aname JOIN ) group by 1
nk)Bf aname JOIN ) group by convert
nk)Bn aname JOIN ) group by aname
nk)Bs aname JOIN ) group by "1"
nk)Bv aname JOIN ) group by @version
nk)E( aname JOIN ) select (
nk)E1 aname JOIN ) select 1
nk)Ef aname JOIN ) select convert
nk)Ek aname JOIN ) select JOIN
nk)En aname JOIN ) select aname
nk)Es aname JOIN ) select "1"
nk)Ev aname JOIN ) select @version
nk)UE aname JOIN ) union select
nk)f( aname JOIN ) convert (
nk)o( aname JOIN ) * (
nk)of aname JOIN ) * convert
nk1 aname JOIN 1
nk1&( aname JOIN 1 and (
nk1&1 aname JOIN 1 and 1
nk1&f aname JOIN 1 and convert
nk1&n aname JOIN 1 and aname
nk1&s aname JOIN 1 and "1"
nk1&v aname JOIN 1 and @version
nk1;E aname JOIN 1 ; select
nk1;T aname JOIN 1 ; DROP
nk1;c aname JOIN 1 ;  -- comment
nk1B( aname JOIN 1 group by (
nk1B1 aname JOIN 1 group by 1
nk1Bf aname JOIN 1 group by convert
nk1Bn aname JOIN 1 group by aname
nk1Bs aname JOIN 1 group by "1"
nk1Bv aname JOIN 1 group by @version
nk1E( aname JOIN 1 select (
nk1E1 aname JOIN 1 select 1
nk1Ef aname JOIN 1 select convert
nk1Ek aname JOIN 1 select JOIN
nk1En aname JOIN 1 select aname
nk1Es aname JOIN 1 select "1"
nk1Ev aname JOIN 1 select @version
nk1U( aname JOIN 1 union (
nk1UE aname JOIN 1 union select
nk1c aname JOIN 1  -- comment
nk1o( aname JOIN 1 * (
nk1of aname JOIN 1 * convert
nk1os aname JOIN 1 * "1"
nk1ov aname JOIN 1 * @version
nkUE( aname JOIN union select (
nkUE1 aname JOIN union select 1
nkUEf aname JOIN union select convert
nkUEk aname JOIN union select JOIN
nkUEn aname JOIN union select aname
nkUEs aname JOIN union select "1"
nkUEv aname JOIN union select @version
nkf() aname JOIN convert ( )
nkf(1 aname JOIN convert ( 1
nkf(f aname JOIN convert ( convert
nkf(n aname JOIN convert ( aname
nkf(s aname JOIN convert ( "1"
nkf(v aname JOIN convert ( @version
nkn aname JOIN aname
nkn&( aname JOIN aname and (
nkn&1 aname JOIN aname and 1
nkn&f aname JOIN aname and convert
nkn&s aname JOIN aname and "1"
nkn&v aname JOIN aname and @version
nkn;E aname JOIN aname ; select
nkn;T aname JOIN aname ; DROP
nkn;c aname JOIN aname ;  -- comment
nknB( aname JOIN aname group by (
nknB1 aname JOIN aname group by 1
nknBf aname JOIN aname group by convert
nknBn aname JOIN aname group by aname
nknBs aname JOIN aname group by "1"
nknBv aname JOIN aname group by @version
nknE( aname JOIN aname select (
nknE1 aname JOIN aname select 1
nknEf aname JOIN aname select convert
nknEs aname JOIN aname select "1"
nknEv aname JOIN aname select @version
nknU( aname JOIN aname union (
nknUE aname JOIN aname union select
nks aname JOIN "1"
nks&( aname JOIN "1" and (
nks&1 aname JOIN "1" and 1
nks&f aname JOIN "1" and convert
nks&n aname JOIN "1" and aname
nks&s aname JOIN "1" and "1"
nks&v aname JOIN "1" and @version
nks; aname JOIN "1" ;
nks;E aname JOIN "1" ; select
nks;T aname JOIN "1" ; DROP
nks;c aname JOIN "1" ;  -- comment
nksB( aname JOIN "1" group by (
nksB1 aname JOIN "1" group by 1
nksBf aname JOIN "1" group by convert
nksBn aname JOIN "1" group by aname
nksBs aname JOIN "1" group by "1"
nksBv aname JOIN "1" group by @version
nksE( aname JOIN "1" select (
nksE1 aname JOIN "1" select 1
nksEf aname JOIN "1" select convert
nksEk aname JOIN "1" select JOIN
nksEn aname JOIN "1" select aname
nksEs aname JOIN "1" select "1"
nksEv aname JOIN "1" select @version
nksU( aname JOIN "1" union (
nksUE aname JOIN "1" union select
nksc aname JOIN "1"  -- comment
nkso( aname JOIN "1" * (
nkso1 aname JOIN "1" * 1
nksof aname JOIN "1" * convert
nkson aname JOIN "1" * aname
nksos aname JOIN "1" * "1"
nksov aname JOIN "1" * @version
nkv aname JOIN @version
nkv&( aname JOIN @version and (
nkv&1 aname JOIN @version and 1
nkv&f aname JOIN @version and convert
nkv&n aname JOIN @version and aname
nkv&s aname JOIN @version and "1"
nkv&v aname JOIN @version and @version
nkv; aname JOIN @version ;
nkv;E aname JOIN @version ; select
nkv;T aname JOIN @version ; DROP
nkv;c aname JOIN @version ;  -- comment
nkvB( aname JOIN @version group by (
nkvB1 aname JOIN @version group by 1
nkvBf aname JOIN @version group by convert
nkvBn aname JOIN @version group by aname
nkvBs aname JOIN @version group by "1"
nkvBv aname JOIN @version group by @version
nkvE( aname JOIN @version select (
nkvE1 aname JOIN @version select 1
nkvEf aname JOIN @version select convert
nkvEk aname JOIN @version select JOIN
nkvEn aname JOIN @version select aname
nkvEs aname JOIN @version select "1"
nkvEv aname JOIN @version select @version
nkvU( aname JOIN @version union (
nkvUE aname JOIN @version union select
nkvc aname JOIN @version  -- comment
nkvo( aname JOIN @version * (
nkvof aname JOIN @version * convert
nkvos aname JOIN @version * "1"
no(1& aname * ( 1 and
no(1) aname * ( 1 )
no(1, aname * ( 1 ,
no(1o aname * ( 1 *
no(E( aname * ( select (
no(E1 aname * ( select 1
no(EE aname * ( select select
no(Ef aname * ( select convert
no(Ek aname * ( select JOIN
no(En aname * ( select aname
no(Eo aname * ( select *
no(Es aname * ( select "1"
no(Ev aname * ( select @version
no(f( aname * ( convert (
no(n& aname * ( aname and
no(n) aname * ( aname )
no(n, aname * ( aname ,
no(no aname * ( aname *
no(s& aname * ( "1" and
no(s) aname * ( "1" )
no(s, aname * ( "1" ,
no(so aname * ( "1" *
no(v& aname * ( @version and
no(v) aname * ( @version )
no(v, aname * ( @version ,
no(vo aname * ( @version *
noU(E aname * union ( select
noUEk aname * union select JOIN
noUEn aname * union select aname
nof() aname * convert ( )
nof(1 aname * convert ( 1
nof(E aname * convert ( select
nof(f aname * convert ( convert
nof(n aname * convert ( aname
nof(s aname * convert ( "1"
nof(v aname * convert ( @version
nok&( aname * JOIN and (
nok(1 aname * JOIN ( 1
nok(f aname * JOIN ( convert
nok(n aname * JOIN ( aname
nok(s aname * JOIN ( "1"
nok(v aname * JOIN ( @version
nok1c aname * JOIN 1  -- comment
nok1o aname * JOIN 1 *
nokf( aname * JOIN convert (
noknc aname * JOIN aname  -- comment
noko( aname * JOIN * (
noko1 aname * JOIN * 1
nokof aname * JOIN * convert
nokon aname * JOIN * aname
nokos aname * JOIN * "1"
nokov aname * JOIN * @version
noksc aname * JOIN "1"  -- comment
nokso aname * JOIN "1" *
nokvc aname * JOIN @version  -- comment
nokvo aname * JOIN @version *
nonsU aname * aname "1" union
nos&( aname * "1" and (
nos&1 aname * "1" and 1
nos&E aname * "1" and select
nos&U aname * "1" and union
nos&f aname * "1" and convert
nos&k aname * "1" and JOIN
nos&n aname * "1" and aname
nos&s aname * "1" and "1"
nos&v aname * "1" and @version
nos(E aname * "1" ( select
nos(U aname * "1" ( union
nos)& aname * "1" ) and
nos), aname * "1" ) ,
nos); aname * "1" ) ;
nos)B aname * "1" ) group by
nos)E aname * "1" ) select
nos)U aname * "1" ) union
nos)c aname * "1" )  -- comment
nos)f aname * "1" ) convert
nos)k aname * "1" ) JOIN
nos)o aname * "1" ) *
nos,( aname * "1" , (
nos,f aname * "1" , convert
nos1( aname * "1" 1 (
nos1U aname * "1" 1 union
nos1f aname * "1" 1 convert
nos1n aname * "1" 1 aname
nos1s aname * "1" 1 "1"
nos1v aname * "1" 1 @version
nos; aname * "1" ;
nos;E aname * "1" ; select
nos;T aname * "1" ; DROP
nos;c aname * "1" ;  -- comment
nosA( aname * "1" COLLATE (
nosAf aname * "1" COLLATE convert
nosAs aname * "1" COLLATE "1"
nosAt aname * "1" COLLATE binary
nosAv aname * "1" COLLATE @version
nosB( aname * "1" group by (
nosB1 aname * "1" group by 1
nosBE aname * "1" group by select
nosBf aname * "1" group by convert
nosBn aname * "1" group by aname
nosBs aname * "1" group by "1"
nosBv aname * "1" group by @version
nosE( aname * "1" select (
nosE1 aname * "1" select 1
nosEU aname * "1" select union
nosEf aname * "1" select convert
nosEk aname * "1" select JOIN
nosEn aname * "1" select aname
nosEo aname * "1" select *
nosEs aname * "1" select "1"
nosEv aname * "1" select @version
nosT( aname * "1" DROP (
nosT1 aname * "1" DROP 1
nosTE aname * "1" DROP select
nosTT aname * "1" DROP DROP
nosTf aname * "1" DROP convert
nosTn aname * "1" DROP aname
nosTs aname * "1" DROP "1"
nosTv aname * "1" DROP @version
nosU aname * "1" union
nosU( aname * "1" union (
nosU1 aname * "1" union 1
nosU; aname * "1" union ;
nosUE aname * "1" union select
nosUT aname * "1" union DROP
nosUc aname * "1" union  -- comment
nosUf aname * "1" union convert
nosUk aname * "1" union JOIN
nosUo aname * "1" union *
nosUs aname * "1" union "1"
nosUv aname * "1" union @version
nosc aname * "1"  -- comment
nosf( aname * "1" convert (
nosk( aname * "1" JOIN (
nosk) aname * "1" JOIN )
nosk1 aname * "1" JOIN 1
noskB aname * "1" JOIN group by
noskU aname * "1" JOIN union
noskf aname * "1" JOIN convert
noskn aname * "1" JOIN aname
nosks aname * "1" JOIN "1"
noskv aname * "1" JOIN @version
nosv( aname * "1" @version (
nosvU aname * "1" @version union
nosvf aname * "1" @version convert
nosvo aname * "1" @version *
nosvs aname * "1" @version "1"
nov&( aname * @version and (
nov&1 aname * @version and 1
nov&E aname * @version and select
nov&U aname * @version and union
nov&f aname * @version and convert
nov&k aname * @version and JOIN
nov&n aname * @version and aname
nov&s aname * @version and "1"
nov&v aname * @version and @version
nov(E aname * @version ( select
nov(U aname * @version ( union
nov)& aname * @version ) and
nov), aname * @version ) ,
nov); aname * @version ) ;
nov)B aname * @version ) group by
nov)E aname * @version ) select
nov)U aname * @version ) union
nov)c aname * @version )  -- comment
nov)f aname * @version ) convert
nov)k aname * @version ) JOIN
nov)o aname * @version ) *
nov,( aname * @version , (
nov,f aname * @version , convert
nov; aname * @version ;
nov;E aname * @version ; select
nov;T aname * @version ; DROP
nov;c aname * @version ;  -- comment
nov;n aname * @version ; aname
novA( aname * @version COLLATE (
novAf aname * @version COLLATE convert
novAs aname * @version COLLATE "1"
novAt aname * @version COLLATE binary
novAv aname * @version COLLATE @version
novB( aname * @version group by (
novB1 aname * @version group by 1
novBE aname * @version group by select
novBf aname * @version group by convert
novBn aname * @version group by aname
novBs aname * @version group by "1"
novBv aname * @version group by @version
novE( aname * @version select (
novE1 aname * @version select 1
novEU aname * @version select union
novEf aname * @version select convert
novEk aname * @version select JOIN
novEn aname * @version select aname
novEo aname * @version select *
novEs aname * @version select "1"
novEv aname * @version select @version
novT( aname * @version DROP (
novT1 aname * @version DROP 1
novTE aname * @version DROP select
novTT aname * @version DROP DROP
novTf aname * @version DROP convert
novTn aname * @version DROP aname
novTs aname * @version DROP "1"
novTv aname * @version DROP @version
novU aname * @version union
novU( aname * @version union (
novU1 aname * @version union 1
novU; aname * @version union ;
novUE aname * @version union select
novUT aname * @version union DROP
novUc aname * @version union  -- comment
novUf aname * @version union convert
novUk aname * @version union JOIN
novUo aname * @version union *
novUs aname * @version union "1"
novUv aname * @version union @version
novc aname * @version  -- comment
novf( aname * @version convert (
novk( aname * @version JOIN (
novk) aname * @version JOIN )
novk1 aname * @version JOIN 1
novkB aname * @version JOIN group by
novkU aname * @version JOIN union
novkf aname * @version JOIN convert
novkn aname * @version JOIN aname
novks aname * @version JOIN "1"
novkv aname * @version JOIN @version
novo( aname * @version * (
novoU aname * @version * union
novof aname * @version * convert
novok aname * @version * JOIN
novos aname * @version * "1"
novs( aname * @version "1" (
novs1 aname * @version "1" 1
novsU aname * @version "1" union
novsf aname * @version "1" convert
novso aname * @version "1" *
novsv aname * @version "1" @version
nsUE aname "1" union select
nsUE; aname "1" union select ;
nsUEc aname "1" union select  -- comment
nsUEk aname "1" union select JOIN
nso1U aname "1" * 1 union
nsonU aname "1" * aname union
nsosU aname "1" * "1" union
nsovU aname "1" * @version union
s&(1& "1" and ( 1 and
s&(1) "1" and ( 1 )
s&(1, "1" and ( 1 ,
s&(1o "1" and ( 1 *
s&(E( "1" and ( select (
s&(E1 "1" and ( select 1
s&(Ef "1" and ( select convert
s&(Ek "1" and ( select JOIN
s&(En "1" and ( select aname
s&(Eo "1" and ( select *
s&(Es "1" and ( select "1"
s&(Ev "1" and ( select @version
s&(f( "1" and ( convert (
s&(n& "1" and ( aname and
s&(n) "1" and ( aname )
s&(n, "1" and ( aname ,
s&(no "1" and ( aname *
s&(s& "1" and ( "1" and
s&(s) "1" and ( "1" )
s&(s, "1" and ( "1" ,
s&(so "1" and ( "1" *
s&(v& "1" and ( @version and
s&(v) "1" and ( @version )
s&(v, "1" and ( @version ,
s&(vo "1" and ( @version *
s&1 "1" and 1
s&1&( "1" and 1 and (
s&1&1 "1" and 1 and 1
s&1&f "1" and 1 and convert
s&1&n "1" and 1 and aname
s&1&s "1" and 1 and "1"
s&1&v "1" and 1 and @version
s&1)& "1" and 1 ) and
s&1)U "1" and 1 ) union
s&1)c "1" and 1 )  -- comment
s&1)o "1" and 1 ) *
s&1; "1" and 1 ;
s&1;E "1" and 1 ; select
s&1;T "1" and 1 ; DROP
s&1;c "1" and 1 ;  -- comment
s&1B( "1" and 1 group by (
s&1B1 "1" and 1 group by 1
s&1Bf "1" and 1 group by convert
s&1Bn "1" and 1 group by aname
s&1Bs "1" and 1 group by "1"
s&1Bv "1" and 1 group by @version
s&1Ek "1" and 1 select JOIN
s&1En "1" and 1 select aname
s&1Tn "1" and 1 DROP aname
s&1U "1" and 1 union
s&1U( "1" and 1 union (
s&1U; "1" and 1 union ;
s&1UE "1" and 1 union select
s&1Uc "1" and 1 union  -- comment
s&1c "1" and 1  -- comment
s&1f( "1" and 1 convert (
s&1k( "1" and 1 JOIN (
s&1k1 "1" and 1 JOIN 1
s&1kf "1" and 1 JOIN convert
s&1kn "1" and 1 JOIN aname
s&1ks "1" and 1 JOIN "1"
s&1kv "1" and 1 JOIN @version
s&1o( "1" and 1 * (
s&1of "1" and 1 * convert
s&1os "1" and 1 * "1"
s&1ov "1" and 1 * @version
s&E(1 "1" and select ( 1
s&E(f "1" and select ( convert
s&E(n "1" and select ( aname
s&E(o "1" and select ( *
s&E(s "1" and select ( "1"
s&E(v "1" and select ( @version
s&E1 "1" and select 1
s&E1; "1" and select 1 ;
s&E1c "1" and select 1  -- comment
s&E1k "1" and select 1 JOIN
s&E1o "1" and select 1 *
s&Ef( "1" and select convert (
s&Ek( "1" and select JOIN (
s&Ek1 "1" and select JOIN 1
s&Ekf "1" and select JOIN convert
s&Ekn "1" and select JOIN aname
s&Eks "1" and select JOIN "1"
s&Ekv "1" and select JOIN @version
s&En "1" and select aname
s&En; "1" and select aname ;
s&Enc "1" and select aname  -- comment
s&Enk "1" and select aname JOIN
s&Eno "1" and select aname *
s&Es "1" and select "1"
s&Es; "1" and select "1" ;
s&Esc "1" and select "1"  -- comment
s&Esk "1" and select "1" JOIN
s&Eso "1" and select "1" *
s&Ev "1" and select @version
s&Ev; "1" and select @version ;
s&Evc "1" and select @version  -- comment
s&Evk "1" and select @version JOIN
s&Evo "1" and select @version *
s&f() "1" and convert ( )
s&f(1 "1" and convert ( 1
s&f(E "1" and convert ( select
s&f(f "1" and convert ( convert
s&f(n "1" and convert ( aname
s&f(s "1" and convert ( "1"
s&f(v "1" and convert ( @version
s&k&( "1" and JOIN and (
s&k&1 "1" and JOIN and 1
s&k&f "1" and JOIN and convert
s&k&n "1" and JOIN and aname
s&k&s "1" and JOIN and "1"
s&k&v "1" and JOIN and @version
s&k(1 "1" and JOIN ( 1
s&k(f "1" and JOIN ( convert
s&k(n "1" and JOIN ( aname
s&k(s "1" and JOIN ( "1"
s&k(v "1" and JOIN ( @version
s&k1o "1" and JOIN 1 *
s&kc "1" and JOIN  -- comment
s&kf( "1" and JOIN convert (
s&knk "1" and JOIN aname JOIN
s&ko( "1" and JOIN * (
s&ko1 "1" and JOIN * 1
s&kof "1" and JOIN * convert
s&kok "1" and JOIN * JOIN
s&kon "1" and JOIN * aname
s&kos "1" and JOIN * "1"
s&kov "1" and JOIN * @version
s&kso "1" and JOIN "1" *
s&kvo "1" and JOIN @version *
s&n "1" and aname
s&n&( "1" and aname and (
s&n&1 "1" and aname and 1
s&n&f "1" and aname and convert
s&n&n "1" and aname and aname
s&n&s "1" and aname and "1"
s&n&v "1" and aname and @version
s&n)& "1" and aname ) and
s&n)U "1" and aname ) union
s&n)c "1" and aname )  -- comment
s&n)o "1" and aname ) *
s&n; "1" and aname ;
s&n;E "1" and aname ; select
s&n;T "1" and aname ; DROP
s&n;c "1" and aname ;  -- comment
s&nB( "1" and aname group by (
s&nB1 "1" and aname group by 1
s&nBf "1" and aname group by convert
s&nBn "1" and aname group by aname
s&nBs "1" and aname group by "1"
s&nBv "1" and aname group by @version
s&nEn "1" and aname select aname
s&nTn "1" and aname DROP aname
s&nU "1" and aname union
s&nU( "1" and aname union (
s&nU; "1" and aname union ;
s&nUE "1" and aname union select
s&nUc "1" and aname union  -- comment
s&nc "1" and aname  -- comment
s&nf( "1" and aname convert (
s&nk( "1" and aname JOIN (
s&nk1 "1" and aname JOIN 1
s&nkf "1" and aname JOIN convert
s&nkn "1" and aname JOIN aname
s&nks "1" and aname JOIN "1"
s&nkv "1" and aname JOIN @version
s&no( "1" and aname * (
s&nof "1" and aname * convert
s&nos "1" and aname * "1"
s&nov "1" and aname * @version
s&s "1" and "1"
s&s&( "1" and "1" and (
s&s&1 "1" and "1" and 1
s&s&f "1" and "1" and convert
s&s&n "1" and "1" and aname
s&s&s "1" and "1" and "1"
s&s&v "1" and "1" and @version
s&s)& "1" and "1" ) and
s&s)U "1" and "1" ) union
s&s)c "1" and "1" )  -- comment
s&s)o "1" and "1" ) *
s&s1 "1" and "1" 1
s&s1; "1" and "1" 1 ;
s&s1c "1" and "1" 1  -- comment
s&s; "1" and "1" ;
s&s;E "1" and "1" ; select
s&s;T "1" and "1" ; DROP
s&s;c "1" and "1" ;  -- comment
s&sB( "1" and "1" group by (
s&sB1 "1" and "1" group by 1
s&sBf "1" and "1" group by convert
s&sBn "1" and "1" group by aname
s&sBs "1" and "1" group by "1"
s&sBv "1" and "1" group by @version
s&sEk "1" and "1" select JOIN
s&sEn "1" and "1" select aname
s&sTn "1" and "1" DROP aname
s&sU "1" and "1" union
s&sU( "1" and "1" union (
s&sU; "1" and "1" union ;
s&sUE "1" and "1" union select
s&sUc "1" and "1" union  -- comment
s&sc "1" and "1"  -- comment
s&sf( "1" and "1" convert (
s&sk( "1" and "1" JOIN (
s&sk1 "1" and "1" JOIN 1
s&skf "1" and "1" JOIN convert
s&skn "1" and "1" JOIN aname
s&sks "1" and "1" JOIN "1"
s&skv "1" and "1" JOIN @version
s&so( "1" and "1" * (
s&so1 "1" and "1" * 1
s&sof "1" and "1" * convert
s&son "1" and "1" * aname
s&sos "1" and "1" * "1"
s&sov "1" and "1" * @version
s&sv "1" and "1" @version
s&sv; "1" and "1" @version ;
s&svc "1" and "1" @version  -- comment
s&svo "1" and "1" @version *
s&v "1" and @version
s&v&( "1" and @version and (
s&v&1 "1" and @version and 1
s&v&f "1" and @version and convert
s&v&n "1" and @version and aname
s&v&s "1" and @version and "1"
s&v&v "1" and @version and @version
s&v)& "1" and @version ) and
s&v)U "1" and @version ) union
s&v)c "1" and @version )  -- comment
s&v)o "1" and @version ) *
s&v; "1" and @version ;
s&v;E "1" and @version ; select
s&v;T "1" and @version ; DROP
s&v;c "1" and @version ;  -- comment
s&vB( "1" and @version group by (
s&vB1 "1" and @version group by 1
s&vBf "1" and @version group by convert
s&vBn "1" and @version group by aname
s&vBs "1" and @version group by "1"
s&vBv "1" and @version group by @version
s&vEk "1" and @version select JOIN
s&vEn "1" and @version select aname
s&vTn "1" and @version DROP aname
s&vU "1" and @version union
s&vU( "1" and @version union (
s&vU; "1" and @version union ;
s&vUE "1" and @version union select
s&vUc "1" and @version union  -- comment
s&vc "1" and @version  -- comment
s&vf( "1" and @version convert (
s&vk( "1" and @version JOIN (
s&vk1 "1" and @version JOIN 1
s&vkf "1" and @version JOIN convert
s&vkn "1" and @version JOIN aname
s&vks "1" and @version JOIN "1"
s&vkv "1" and @version JOIN @version
s&vo( "1" and @version * (
s&vof "1" and @version * convert
s&vos "1" and @version * "1"
s&vs "1" and @version "1"
s&vs; "1" and @version "1" ;
s&vsc "1" and @version "1"  -- comment
s&vso "1" and @version "1" *
s(Ef( "1" ( select convert (
s(Ekf "1" ( select JOIN convert
s(Ekn "1" ( select JOIN aname
s(Enk "1" ( select aname JOIN
s(U(E "1" ( union ( select
s)&(1 "1" ) and ( 1
s)&(E "1" ) and ( select
s)&(f "1" ) and ( convert
s)&(n "1" ) and ( aname
s)&(s "1" ) and ( "1"
s)&(v "1" ) and ( @version
s)&1 "1" ) and 1
s)&1& "1" ) and 1 and
s)&1) "1" ) and 1 )
s)&1; "1" ) and 1 ;
s)&1B "1" ) and 1 group by
s)&1U "1" ) and 1 union
s)&1c "1" ) and 1  -- comment
s)&1f "1" ) and 1 convert
s)&1o "1" ) and 1 *
s)&f( "1" ) and convert (
s)&n "1" ) and aname
s)&n& "1" ) and aname and
s)&n) "1" ) and aname )
s)&n; "1" ) and aname ;
s)&nB "1" ) and aname group by
s)&nU "1" ) and aname union
s)&nc "1" ) and aname  -- comment
s)&nf "1" ) and aname convert
s)&no "1" ) and aname *
s)&s "1" ) and "1"
s)&s& "1" ) and "1" and
s)&s) "1" ) and "1" )
s)&s; "1" ) and "1" ;
s)&sB "1" ) and "1" group by
s)&sU "1" ) and "1" union
s)&sc "1" ) and "1"  -- comment
s)&sf "1" ) and "1" convert
s)&so "1" ) and "1" *
s)&v "1" ) and @version
s)&v& "1" ) and @version and
s)&v) "1" ) and @version )
s)&v; "1" ) and @version ;
s)&vB "1" ) and @version group by
s)&vU "1" ) and @version union
s)&vc "1" ) and @version  -- comment
s)&vf "1" ) and @version convert
s)&vo "1" ) and @version *
s),(1 "1" ) , ( 1
s),(f "1" ) , ( convert
s),(n "1" ) , ( aname
s),(s "1" ) , ( "1"
s),(v "1" ) , ( @version
s);E( "1" ) ; select (
s);E1 "1" ) ; select 1
s);Ef "1" ) ; select convert
s);Ek "1" ) ; select JOIN
s);En "1" ) ; select aname
s);Eo "1" ) ; select *
s);Es "1" ) ; select "1"
s);Ev "1" ) ; select @version
s);T( "1" ) ; DROP (
s);T1 "1" ) ; DROP 1
s);Tf "1" ) ; DROP convert
s);Tk "1" ) ; DROP JOIN
s);Tn "1" ) ; DROP aname
s);To "1" ) ; DROP *
s);Ts "1" ) ; DROP "1"
s);Tv "1" ) ; DROP @version
s)B(1 "1" ) group by ( 1
s)B(f "1" ) group by ( convert
s)B(n "1" ) group by ( aname
s)B(s "1" ) group by ( "1"
s)B(v "1" ) group by ( @version
s)B1 "1" ) group by 1
s)B1& "1" ) group by 1 and
s)B1; "1" ) group by 1 ;
s)B1U "1" ) group by 1 union
s)B1c "1" ) group by 1  -- comment
s)B1k "1" ) group by 1 JOIN
s)B1n "1" ) group by 1 aname
s)B1o "1" ) group by 1 *
s)Bf( "1" ) group by convert (
s)Bn "1" ) group by aname
s)Bn& "1" ) group by aname and
s)Bn; "1" ) group by aname ;
s)BnU "1" ) group by aname union
s)Bnc "1" ) group by aname  -- comment
s)Bnk "1" ) group by aname JOIN
s)Bno "1" ) group by aname *
s)Bs "1" ) group by "1"
s)Bs& "1" ) group by "1" and
s)Bs; "1" ) group by "1" ;
s)BsU "1" ) group by "1" union
s)Bsc "1" ) group by "1"  -- comment
s)Bsk "1" ) group by "1" JOIN
s)Bso "1" ) group by "1" *
s)Bv "1" ) group by @version
s)Bv& "1" ) group by @version and
s)Bv; "1" ) group by @version ;
s)BvU "1" ) group by @version union
s)Bvc "1" ) group by @version  -- comment
s)Bvk "1" ) group by @version JOIN
s)Bvo "1" ) group by @version *
s)E(1 "1" ) select ( 1
s)E(f "1" ) select ( convert
s)E(n "1" ) select ( aname
s)E(s "1" ) select ( "1"
s)E(v "1" ) select ( @version
s)E1c "1" ) select 1  -- comment
s)E1o "1" ) select 1 *
s)Ef( "1" ) select convert (
s)Ek( "1" ) select JOIN (
s)Ek1 "1" ) select JOIN 1
s)Ekf "1" ) select JOIN convert
s)Ekn "1" ) select JOIN aname
s)Eks "1" ) select JOIN "1"
s)Ekv "1" ) select JOIN @version
s)Enc "1" ) select aname  -- comment
s)Eno "1" ) select aname *
s)Esc "1" ) select "1"  -- comment
s)Eso "1" ) select "1" *
s)Evc "1" ) select @version  -- comment
s)Evo "1" ) select @version *
s)U(E "1" ) union ( select
s)UE( "1" ) union select (
s)UE1 "1" ) union select 1
s)UEf "1" ) union select convert
s)UEk "1" ) union select JOIN
s)UEn "1" ) union select aname
s)UEs "1" ) union select "1"
s)UEv "1" ) union select @version
s)c "1" )  -- comment
s)f(f "1" ) convert ( convert
s)k(1 "1" ) JOIN ( 1
s)k(f "1" ) JOIN ( convert
s)k(n "1" ) JOIN ( aname
s)k(s "1" ) JOIN ( "1"
s)k(v "1" ) JOIN ( @version
s)k1& "1" ) JOIN 1 and
s)k1; "1" ) JOIN 1 ;
s)k1B "1" ) JOIN 1 group by
s)k1E "1" ) JOIN 1 select
s)k1U "1" ) JOIN 1 union
s)k1o "1" ) JOIN 1 *
s)kB( "1" ) JOIN group by (
s)kB1 "1" ) JOIN group by 1
s)kBf "1" ) JOIN group by convert
s)kBn "1" ) JOIN group by aname
s)kBs "1" ) JOIN group by "1"
s)kBv "1" ) JOIN group by @version
s)kUE "1" ) JOIN union select
s)kf( "1" ) JOIN convert (
s)kn& "1" ) JOIN aname and
s)kn; "1" ) JOIN aname ;
s)knB "1" ) JOIN aname group by
s)knE "1" ) JOIN aname select
s)knU "1" ) JOIN aname union
s)knc "1" ) JOIN aname  -- comment
s)knk "1" ) JOIN aname JOIN
s)ks& "1" ) JOIN "1" and
s)ks; "1" ) JOIN "1" ;
s)ksB "1" ) JOIN "1" group by
s)ksE "1" ) JOIN "1" select
s)ksU "1" ) JOIN "1" union
s)kso "1" ) JOIN "1" *
s)kv& "1" ) JOIN @version and
s)kv; "1" ) JOIN @version ;
s)kvB "1" ) JOIN @version group by
s)kvE "1" ) JOIN @version select
s)kvU "1" ) JOIN @version union
s)kvo "1" ) JOIN @version *
s)o(1 "1" ) * ( 1
s)o(E "1" ) * ( select
s)o(f "1" ) * ( convert
s)o(n "1" ) * ( aname
s)o(s "1" ) * ( "1"
s)o(v "1" ) * ( @version
s)o1 "1" ) * 1
s)o1& "1" ) * 1 and
s)o1) "1" ) * 1 )
s)o1; "1" ) * 1 ;
s)o1B "1" ) * 1 group by
s)o1U "1" ) * 1 union
s)o1c "1" ) * 1  -- comment
s)o1k "1" ) * 1 JOIN
s)of( "1" ) * convert (
s)on& "1" ) * aname and
s)on) "1" ) * aname )
s)on; "1" ) * aname ;
s)onB "1" ) * aname group by
s)onU "1" ) * aname union
s)onc "1" ) * aname  -- comment
s)onk "1" ) * aname JOIN
s)os "1" ) * "1"
s)os& "1" ) * "1" and
s)os) "1" ) * "1" )
s)os; "1" ) * "1" ;
s)osB "1" ) * "1" group by
s)osU "1" ) * "1" union
s)osc "1" ) * "1"  -- comment
s)osk "1" ) * "1" JOIN
s)ov "1" ) * @version
s)ov& "1" ) * @version and
s)ov) "1" ) * @version )
s)ov; "1" ) * @version ;
s)ovB "1" ) * @version group by
s)ovU "1" ) * @version union
s)ovc "1" ) * @version  -- comment
s)ovk "1" ) * @version JOIN
s)ovo "1" ) * @version *
s,(1) "1" , ( 1 )
s,(1o "1" , ( 1 *
s,(E( "1" , ( select (
s,(E1 "1" , ( select 1
s,(Ef "1" , ( select convert
s,(Ek "1" , ( select JOIN
s,(En "1" , ( select aname
s,(Es "1" , ( select "1"
s,(Ev "1" , ( select @version
s,(f( "1" , ( convert (
s,(n) "1" , ( aname )
s,(no "1" , ( aname *
s,(s) "1" , ( "1" )
s,(so "1" , ( "1" *
s,(v) "1" , ( @version )
s,(vo "1" , ( @version *
s,f() "1" , convert ( )
s,f(1 "1" , convert ( 1
s,f(f "1" , convert ( convert
s,f(n "1" , convert ( aname
s,f(s "1" , convert ( "1"
s,f(v "1" , convert ( @version
s1UE "1" 1 union select
s1UE; "1" 1 union select ;
s1UEc "1" 1 union select  -- comment
s1UEk "1" 1 union select JOIN
s1f() "1" 1 convert ( )
s1f(1 "1" 1 convert ( 1
s1f(f "1" 1 convert ( convert
s1f(n "1" 1 convert ( aname
s1f(s "1" 1 convert ( "1"
s1f(v "1" 1 convert ( @version
s1nc "1" 1 aname  -- comment
s1s; "1" 1 "1" ;
s1s;c "1" 1 "1" ;  -- comment
s1sc "1" 1 "1"  -- comment
s1v "1" 1 @version
s1v; "1" 1 @version ;
s1v;c "1" 1 @version ;  -- comment
s1vc "1" 1 @version  -- comment
s1vo( "1" 1 @version * (
s1vof "1" 1 @version * convert
s1vos "1" 1 @version * "1"
s;E(1 "1" ; select ( 1
s;E(E "1" ; select ( select
s;E(f "1" ; select ( convert
s;E(n "1" ; select ( aname
s;E(s "1" ; select ( "1"
s;E(v "1" ; select ( @version
s;E1, "1" ; select 1 ,
s;E1; "1" ; select 1 ;
s;E1T "1" ; select 1 DROP
s;E1c "1" ; select 1  -- comment
s;E1k "1" ; select 1 JOIN
s;E1o "1" ; select 1 *
s;Ef( "1" ; select convert (
s;Ek( "1" ; select JOIN (
s;Ek1 "1" ; select JOIN 1
s;Ekf "1" ; select JOIN convert
s;Ekn "1" ; select JOIN aname
s;Eko "1" ; select JOIN *
s;Eks "1" ; select JOIN "1"
s;Ekv "1" ; select JOIN @version
s;En, "1" ; select aname ,
s;En; "1" ; select aname ;
s;EnE "1" ; select aname select
s;EnT "1" ; select aname DROP
s;Enc "1" ; select aname  -- comment
s;Enk "1" ; select aname JOIN
s;Eno "1" ; select aname *
s;Es, "1" ; select "1" ,
s;Es; "1" ; select "1" ;
s;EsT "1" ; select "1" DROP
s;Esc "1" ; select "1"  -- comment
s;Esk "1" ; select "1" JOIN
s;Eso "1" ; select "1" *
s;Ev, "1" ; select @version ,
s;Ev; "1" ; select @version ;
s;EvT "1" ; select @version DROP
s;Evc "1" ; select @version  -- comment
s;Evk "1" ; select @version JOIN
s;Evo "1" ; select @version *
s;T(1 "1" ; DROP ( 1
s;T(E "1" ; DROP ( select
s;T(c "1" ; DROP (  -- comment
s;T(f "1" ; DROP ( convert
s;T(n "1" ; DROP ( aname
s;T(s "1" ; DROP ( "1"
s;T(v "1" ; DROP ( @version
s;T1( "1" ; DROP 1 (
s;T1, "1" ; DROP 1 ,
s;T1; "1" ; DROP 1 ;
s;T1T "1" ; DROP 1 DROP
s;T1c "1" ; DROP 1  -- comment
s;T1f "1" ; DROP 1 convert
s;T1k "1" ; DROP 1 JOIN
s;T1o "1" ; DROP 1 *
s;T; "1" ; DROP ;
s;T;c "1" ; DROP ;  -- comment
s;TTn "1" ; DROP DROP aname
s;Tf( "1" ; DROP convert (
s;Tk( "1" ; DROP JOIN (
s;Tk1 "1" ; DROP JOIN 1
s;Tkf "1" ; DROP JOIN convert
s;Tkk "1" ; DROP JOIN JOIN
s;Tkn "1" ; DROP JOIN aname
s;Tko "1" ; DROP JOIN *
s;Tks "1" ; DROP JOIN "1"
s;Tkv "1" ; DROP JOIN @version
s;Tn( "1" ; DROP aname (
s;Tn, "1" ; DROP aname ,
s;Tn1 "1" ; DROP aname 1
s;Tn; "1" ; DROP aname ;
s;TnE "1" ; DROP aname select
s;TnT "1" ; DROP aname DROP
s;Tnc "1" ; DROP aname  -- comment
s;Tnf "1" ; DROP aname convert
s;Tnk "1" ; DROP aname JOIN
s;Tnn "1" ; DROP aname aname
s;Tno "1" ; DROP aname *
s;Tns "1" ; DROP aname "1"
s;Tnv "1" ; DROP aname @version
s;To( "1" ; DROP * (
s;Ts( "1" ; DROP "1" (
s;Ts, "1" ; DROP "1" ,
s;Ts; "1" ; DROP "1" ;
s;TsT "1" ; DROP "1" DROP
s;Tsc "1" ; DROP "1"  -- comment
s;Tsf "1" ; DROP "1" convert
s;Tsk "1" ; DROP "1" JOIN
s;Tso "1" ; DROP "1" *
s;Tv( "1" ; DROP @version (
s;Tv, "1" ; DROP @version ,
s;Tv; "1" ; DROP @version ;
s;TvT "1" ; DROP @version DROP
s;Tvc "1" ; DROP @version  -- comment
s;Tvf "1" ; DROP @version convert
s;Tvk "1" ; DROP @version JOIN
s;Tvo "1" ; DROP @version *
s;n:T "1" ; aname : DROP
sA(f( "1" COLLATE ( convert (
sA(n) "1" COLLATE ( aname )
sA(no "1" COLLATE ( aname *
sA(s) "1" COLLATE ( "1" )
sA(so "1" COLLATE ( "1" *
sA(v) "1" COLLATE ( @version )
sA(vo "1" COLLATE ( @version *
sAf() "1" COLLATE convert ( )
sAf(1 "1" COLLATE convert ( 1
sAf(f "1" COLLATE convert ( convert
sAf(n "1" COLLATE convert ( aname
sAf(s "1" COLLATE convert ( "1"
sAf(v "1" COLLATE convert ( @version
sAsUE "1" COLLATE "1" union select
sAso( "1" COLLATE "1" * (
sAso1 "1" COLLATE "1" * 1
sAsof "1" COLLATE "1" * convert
sAson "1" COLLATE "1" * aname
sAsos "1" COLLATE "1" * "1"
sAsov "1" COLLATE "1" * @version
sAtUE "1" COLLATE binary union select
sAto( "1" COLLATE binary * (
sAto1 "1" COLLATE binary * 1
sAtof "1" COLLATE binary * convert
sAton "1" COLLATE binary * aname
sAtos "1" COLLATE binary * "1"
sAtov "1" COLLATE binary * @version
sAvUE "1" COLLATE @version union select
sAvo( "1" COLLATE @version * (
sAvof "1" COLLATE @version * convert
sAvos "1" COLLATE @version * "1"
sB(1) "1" group by ( 1 )
sB(1o "1" group by ( 1 *
sB(f( "1" group by ( convert (
sB(no "1" group by ( aname *
sB(s) "1" group by ( "1" )
sB(so "1" group by ( "1" *
sB(v) "1" group by ( @version )
sB(vo "1" group by ( @version *
sB1 "1" group by 1
sB1&( "1" group by 1 and (
sB1&1 "1" group by 1 and 1
sB1&f "1" group by 1 and convert
sB1&n "1" group by 1 and aname
sB1&s "1" group by 1 and "1"
sB1&v "1" group by 1 and @version
sB1,( "1" group by 1 , (
sB1,f "1" group by 1 , convert
sB1; "1" group by 1 ;
sB1;c "1" group by 1 ;  -- comment
sB1B( "1" group by 1 group by (
sB1B1 "1" group by 1 group by 1
sB1Bf "1" group by 1 group by convert
sB1Bn "1" group by 1 group by aname
sB1Bs "1" group by 1 group by "1"
sB1Bv "1" group by 1 group by @version
sB1U( "1" group by 1 union (
sB1UE "1" group by 1 union select
sB1c "1" group by 1  -- comment
sB1k( "1" group by 1 JOIN (
sB1k1 "1" group by 1 JOIN 1
sB1kf "1" group by 1 JOIN convert
sB1kn "1" group by 1 JOIN aname
sB1ks "1" group by 1 JOIN "1"
sB1kv "1" group by 1 JOIN @version
sB1o( "1" group by 1 * (
sB1of "1" group by 1 * convert
sB1os "1" group by 1 * "1"
sB1ov "1" group by 1 * @version
sBE(1 "1" group by select ( 1
sBE(f "1" group by select ( convert
sBE(n "1" group by select ( aname
sBE(s "1" group by select ( "1"
sBE(v "1" group by select ( @version
sBEk( "1" group by select JOIN (
sBf() "1" group by convert ( )
sBf(1 "1" group by convert ( 1
sBf(f "1" group by convert ( convert
sBf(n "1" group by convert ( aname
sBf(s "1" group by convert ( "1"
sBf(v "1" group by convert ( @version
sBn "1" group by aname
sBn&( "1" group by aname and (
sBn&1 "1" group by aname and 1
sBn&f "1" group by aname and convert
sBn&n "1" group by aname and aname
sBn&s "1" group by aname and "1"
sBn&v "1" group by aname and @version
sBn,( "1" group by aname , (
sBn,f "1" group by aname , convert
sBn; "1" group by aname ;
sBn;c "1" group by aname ;  -- comment
sBnB( "1" group by aname group by (
sBnB1 "1" group by aname group by 1
sBnBf "1" group by aname group by convert
sBnBn "1" group by aname group by aname
sBnBs "1" group by aname group by "1"
sBnBv "1" group by aname group by @version
sBnU( "1" group by aname union (
sBnUE "1" group by aname union select
sBnc "1" group by aname  -- comment
sBnk( "1" group by aname JOIN (
sBnk1 "1" group by aname JOIN 1
sBnkf "1" group by aname JOIN convert
sBnkn "1" group by aname JOIN aname
sBnks "1" group by aname JOIN "1"
sBnkv "1" group by aname JOIN @version
sBno( "1" group by aname * (
sBnof "1" group by aname * convert
sBnos "1" group by aname * "1"
sBnov "1" group by aname * @version
sBs "1" group by "1"
sBs&( "1" group by "1" and (
sBs&1 "1" group by "1" and 1
sBs&f "1" group by "1" and convert
sBs&n "1" group by "1" and aname
sBs&s "1" group by "1" and "1"
sBs&v "1" group by "1" and @version
sBs,( "1" group by "1" , (
sBs,f "1" group by "1" , convert
sBs; "1" group by "1" ;
sBs;c "1" group by "1" ;  -- comment
sBsB( "1" group by "1" group by (
sBsB1 "1" group by "1" group by 1
sBsBf "1" group by "1" group by convert
sBsBn "1" group by "1" group by aname
sBsBs "1" group by "1" group by "1"
sBsBv "1" group by "1" group by @version
sBsU( "1" group by "1" union (
sBsUE "1" group by "1" union select
sBsc "1" group by "1"  -- comment
sBsk( "1" group by "1" JOIN (
sBsk1 "1" group by "1" JOIN 1
sBskf "1" group by "1" JOIN convert
sBskn "1" group by "1" JOIN aname
sBsks "1" group by "1" JOIN "1"
sBskv "1" group by "1" JOIN @version
sBso( "1" group by "1" * (
sBso1 "1" group by "1" * 1
sBsof "1" group by "1" * convert
sBson "1" group by "1" * aname
sBsos "1" group by "1" * "1"
sBsov "1" group by "1" * @version
sBv "1" group by @version
sBv&( "1" group by @version and (
sBv&1 "1" group by @version and 1
sBv&f "1" group by @version and convert
sBv&n "1" group by @version and aname
sBv&s "1" group by @version and "1"
sBv&v "1" group by @version and @version
sBv,( "1" group by @version , (
sBv,f "1" group by @version , convert
sBv; "1" group by @version ;
sBv;c "1" group by @version ;  -- comment
sBvB( "1" group by @version group by (
sBvB1 "1" group by @version group by 1
sBvBf "1" group by @version group by convert
sBvBn "1" group by @version group by aname
sBvBs "1" group by @version group by "1"
sBvBv "1" group by @version group by @version
sBvU( "1" group by @version union (
sBvUE "1" group by @version union select
sBvc "1" group by @version  -- comment
sBvk( "1" group by @version JOIN (
sBvk1 "1" group by @version JOIN 1
sBvkf "1" group by @version JOIN convert
sBvkn "1" group by @version JOIN aname
sBvks "1" group by @version JOIN "1"
sBvkv "1" group by @version JOIN @version
sBvo( "1" group by @version * (
sBvof "1" group by @version * convert
sBvos "1" group by @version * "1"
sE(1) "1" select ( 1 )
sE(1o "1" select ( 1 *
sE(f( "1" select ( convert (
sE(n) "1" select ( aname )
sE(no "1" select ( aname *
sE(s) "1" select ( "1" )
sE(so "1" select ( "1" *
sE(v) "1" select ( @version )
sE(vo "1" select ( @version *
sE1;T "1" select 1 ; DROP
sE1T( "1" select 1 DROP (
sE1T1 "1" select 1 DROP 1
sE1Tf "1" select 1 DROP convert
sE1Tn "1" select 1 DROP aname
sE1Ts "1" select 1 DROP "1"
sE1Tv "1" select 1 DROP @version
sE1UE "1" select 1 union select
sE1c "1" select 1  -- comment
sE1o( "1" select 1 * (
sE1of "1" select 1 * convert
sE1os "1" select 1 * "1"
sE1ov "1" select 1 * @version
sEU(1 "1" select union ( 1
sEU(f "1" select union ( convert
sEU(n "1" select union ( aname
sEU(s "1" select union ( "1"
sEU(v "1" select union ( @version
sEU1, "1" select union 1 ,
sEU1c "1" select union 1  -- comment
sEU1o "1" select union 1 *
sEUEf "1" select union select convert
sEUEk "1" select union select JOIN
sEUf( "1" select union convert (
sEUs, "1" select union "1" ,
sEUsc "1" select union "1"  -- comment
sEUso "1" select union "1" *
sEUv, "1" select union @version ,
sEUvc "1" select union @version  -- comment
sEUvo "1" select union @version *
sEf() "1" select convert ( )
sEf(1 "1" select convert ( 1
sEf(f "1" select convert ( convert
sEf(n "1" select convert ( aname
sEf(s "1" select convert ( "1"
sEf(v "1" select convert ( @version
sEk(1 "1" select JOIN ( 1
sEk(E "1" select JOIN ( select
sEk(f "1" select JOIN ( convert
sEk(n "1" select JOIN ( aname
sEk(s "1" select JOIN ( "1"
sEk(v "1" select JOIN ( @version
sEk1; "1" select JOIN 1 ;
sEk1T "1" select JOIN 1 DROP
sEk1U "1" select JOIN 1 union
sEk1c "1" select JOIN 1  -- comment
sEk1o "1" select JOIN 1 *
sEkU( "1" select JOIN union (
sEkU1 "1" select JOIN union 1
sEkUE "1" select JOIN union select
sEkUf "1" select JOIN union convert
sEkUs "1" select JOIN union "1"
sEkUv "1" select JOIN union @version
sEkf( "1" select JOIN convert (
sEkn; "1" select JOIN aname ;
sEknE "1" select JOIN aname select
sEknT "1" select JOIN aname DROP
sEknU "1" select JOIN aname union
sEknc "1" select JOIN aname  -- comment
sEkok "1" select JOIN * JOIN
sEks; "1" select JOIN "1" ;
sEksT "1" select JOIN "1" DROP
sEksU "1" select JOIN "1" union
sEksc "1" select JOIN "1"  -- comment
sEkso "1" select JOIN "1" *
sEkv; "1" select JOIN @version ;
sEkvT "1" select JOIN @version DROP
sEkvU "1" select JOIN @version union
sEkvc "1" select JOIN @version  -- comment
sEkvo "1" select JOIN @version *
sEn;T "1" select aname ; DROP
sEnEn "1" select aname select aname
sEnT( "1" select aname DROP (
sEnT1 "1" select aname DROP 1
sEnTf "1" select aname DROP convert
sEnTn "1" select aname DROP aname
sEnTs "1" select aname DROP "1"
sEnTv "1" select aname DROP @version
sEnUE "1" select aname union select
sEnc "1" select aname  -- comment
sEno( "1" select aname * (
sEnof "1" select aname * convert
sEnos "1" select aname * "1"
sEnov "1" select aname * @version
sEokn "1" select * JOIN aname
sEs;T "1" select "1" ; DROP
sEsT( "1" select "1" DROP (
sEsT1 "1" select "1" DROP 1
sEsTf "1" select "1" DROP convert
sEsTn "1" select "1" DROP aname
sEsTs "1" select "1" DROP "1"
sEsTv "1" select "1" DROP @version
sEsUE "1" select "1" union select
sEsc "1" select "1"  -- comment
sEso( "1" select "1" * (
sEso1 "1" select "1" * 1
sEsof "1" select "1" * convert
sEson "1" select "1" * aname
sEsos "1" select "1" * "1"
sEsov "1" select "1" * @version
sEv;T "1" select @version ; DROP
sEvT( "1" select @version DROP (
sEvT1 "1" select @version DROP 1
sEvTf "1" select @version DROP convert
sEvTn "1" select @version DROP aname
sEvTs "1" select @version DROP "1"
sEvTv "1" select @version DROP @version
sEvUE "1" select @version union select
sEvc "1" select @version  -- comment
sEvo( "1" select @version * (
sEvof "1" select @version * convert
sEvos "1" select @version * "1"
sT(1) "1" DROP ( 1 )
sT(1o "1" DROP ( 1 *
sT(f( "1" DROP ( convert (
sT(n) "1" DROP ( aname )
sT(no "1" DROP ( aname *
sT(s) "1" DROP ( "1" )
sT(so "1" DROP ( "1" *
sT(v) "1" DROP ( @version )
sT(vo "1" DROP ( @version *
sT1(f "1" DROP 1 ( convert
sT1o( "1" DROP 1 * (
sT1of "1" DROP 1 * convert
sT1os "1" DROP 1 * "1"
sT1ov "1" DROP 1 * @version
sTE(1 "1" DROP select ( 1
sTE(f "1" DROP select ( convert
sTE(n "1" DROP select ( aname
sTE(s "1" DROP select ( "1"
sTE(v "1" DROP select ( @version
sTE1n "1" DROP select 1 aname
sTE1o "1" DROP select 1 *
sTEf( "1" DROP select convert (
sTEk( "1" DROP select JOIN (
sTEk1 "1" DROP select JOIN 1
sTEkf "1" DROP select JOIN convert
sTEkn "1" DROP select JOIN aname
sTEks "1" DROP select JOIN "1"
sTEkv "1" DROP select JOIN @version
sTEnn "1" DROP select aname aname
sTEno "1" DROP select aname *
sTEsn "1" DROP select "1" aname
sTEso "1" DROP select "1" *
sTEvn "1" DROP select @version aname
sTEvo "1" DROP select @version *
sTTnE "1" DROP DROP aname select
sTTnT "1" DROP DROP aname DROP
sTTnk "1" DROP DROP aname JOIN
sTTnn "1" DROP DROP aname aname
sTf() "1" DROP convert ( )
sTf(1 "1" DROP convert ( 1
sTf(f "1" DROP convert ( convert
sTf(n "1" DROP convert ( aname
sTf(s "1" DROP convert ( "1"
sTf(v "1" DROP convert ( @version
sTn(1 "1" DROP aname ( 1
sTn(f "1" DROP aname ( convert
sTn(s "1" DROP aname ( "1"
sTn(v "1" DROP aname ( @version
sTn1c "1" DROP aname 1  -- comment
sTn1o "1" DROP aname 1 *
sTn;E "1" DROP aname ; select
sTn;T "1" DROP aname ; DROP
sTn;n "1" DROP aname ; aname
sTnE( "1" DROP aname select (
sTnE1 "1" DROP aname select 1
sTnEf "1" DROP aname select convert
sTnEn "1" DROP aname select aname
sTnEs "1" DROP aname select "1"
sTnEv "1" DROP aname select @version
sTnT( "1" DROP aname DROP (
sTnT1 "1" DROP aname DROP 1
sTnTf "1" DROP aname DROP convert
sTnTn "1" DROP aname DROP aname
sTnTs "1" DROP aname DROP "1"
sTnTv "1" DROP aname DROP @version
sTnf( "1" DROP aname convert (
sTnkn "1" DROP aname JOIN aname
sTnn: "1" DROP aname aname :
sTnnc "1" DROP aname aname  -- comment
sTnno "1" DROP aname aname *
sTno( "1" DROP aname * (
sTnof "1" DROP aname * convert
sTnos "1" DROP aname * "1"
sTnov "1" DROP aname * @version
sTnsc "1" DROP aname "1"  -- comment
sTnso "1" DROP aname "1" *
sTnvc "1" DROP aname @version  -- comment
sTnvo "1" DROP aname @version *
sTs(f "1" DROP "1" ( convert
sTso( "1" DROP "1" * (
sTso1 "1" DROP "1" * 1
sTsof "1" DROP "1" * convert
sTson "1" DROP "1" * aname
sTsos "1" DROP "1" * "1"
sTsov "1" DROP "1" * @version
sTv(1 "1" DROP @version ( 1
sTv(f "1" DROP @version ( convert
sTvo( "1" DROP @version * (
sTvof "1" DROP @version * convert
sTvos "1" DROP @version * "1"
sU(1) "1" union ( 1 )
sU(1o "1" union ( 1 *
sU(E( "1" union ( select (
sU(E1 "1" union ( select 1
sU(Ef "1" union ( select convert
sU(Ek "1" union ( select JOIN
sU(En "1" union ( select aname
sU(Es "1" union ( select "1"
sU(Ev "1" union ( select @version
sU(f( "1" union ( convert (
sU(n) "1" union ( aname )
sU(no "1" union ( aname *
sU(s) "1" union ( "1" )
sU(so "1" union ( "1" *
sU(v) "1" union ( @version )
sU(vo "1" union ( @version *
sU1,( "1" union 1 , (
sU1,f "1" union 1 , convert
sU1c "1" union 1  -- comment
sU1o( "1" union 1 * (
sU1of "1" union 1 * convert
sU1os "1" union 1 * "1"
sU1ov "1" union 1 * @version
sU; "1" union ;
sU;c "1" union ;  -- comment
sUE "1" union select
sUE(1 "1" union select ( 1
sUE(E "1" union select ( select
sUE(f "1" union select ( convert
sUE(n "1" union select ( aname
sUE(o "1" union select ( *
sUE(s "1" union select ( "1"
sUE(v "1" union select ( @version
sUE1 "1" union select 1
sUE1& "1" union select 1 and
sUE1( "1" union select 1 (
sUE1) "1" union select 1 )
sUE1, "1" union select 1 ,
sUE1; "1" union select 1 ;
sUE1B "1" union select 1 group by
sUE1U "1" union select 1 union
sUE1c "1" union select 1  -- comment
sUE1f "1" union select 1 convert
sUE1k "1" union select 1 JOIN
sUE1n "1" union select 1 aname
sUE1o "1" union select 1 *
sUE1s "1" union select 1 "1"
sUE1v "1" union select 1 @version
sUE; "1" union select ;
sUE;c "1" union select ;  -- comment
sUEc "1" union select  -- comment
sUEf "1" union select convert
sUEf( "1" union select convert (
sUEf, "1" union select convert ,
sUEf; "1" union select convert ;
sUEfc "1" union select convert  -- comment
sUEk "1" union select JOIN
sUEk( "1" union select JOIN (
sUEk1 "1" union select JOIN 1
sUEk; "1" union select JOIN ;
sUEkc "1" union select JOIN  -- comment
sUEkf "1" union select JOIN convert
sUEkn "1" union select JOIN aname
sUEko "1" union select JOIN *
sUEks "1" union select JOIN "1"
sUEkv "1" union select JOIN @version
sUEn "1" union select aname
sUEn& "1" union select aname and
sUEn( "1" union select aname (
sUEn) "1" union select aname )
sUEn, "1" union select aname ,
sUEn1 "1" union select aname 1
sUEn; "1" union select aname ;
sUEnB "1" union select aname group by
sUEnU "1" union select aname union
sUEnc "1" union select aname  -- comment
sUEnf "1" union select aname convert
sUEnk "1" union select aname JOIN
sUEno "1" union select aname *
sUEns "1" union select aname "1"
sUEok "1" union select * JOIN
sUEon "1" union select * aname
sUEs "1" union select "1"
sUEs& "1" union select "1" and
sUEs( "1" union select "1" (
sUEs) "1" union select "1" )
sUEs, "1" union select "1" ,
sUEs1 "1" union select "1" 1
sUEs; "1" union select "1" ;
sUEsB "1" union select "1" group by
sUEsU "1" union select "1" union
sUEsc "1" union select "1"  -- comment
sUEsf "1" union select "1" convert
sUEsk "1" union select "1" JOIN
sUEso "1" union select "1" *
sUEsv "1" union select "1" @version
sUEv "1" union select @version
sUEv& "1" union select @version and
sUEv( "1" union select @version (
sUEv) "1" union select @version )
sUEv, "1" union select @version ,
sUEv; "1" union select @version ;
sUEvB "1" union select @version group by
sUEvU "1" union select @version union
sUEvc "1" union select @version  -- comment
sUEvf "1" union select @version convert
sUEvk "1" union select @version JOIN
sUEvn "1" union select @version aname
sUEvo "1" union select @version *
sUEvs "1" union select @version "1"
sUTn( "1" union DROP aname (
sUTn1 "1" union DROP aname 1
sUTnf "1" union DROP aname convert
sUTnn "1" union DROP aname aname
sUTns "1" union DROP aname "1"
sUTnv "1" union DROP aname @version
sUc "1" union  -- comment
sUf() "1" union convert ( )
sUf(1 "1" union convert ( 1
sUf(f "1" union convert ( convert
sUf(n "1" union convert ( aname
sUf(s "1" union convert ( "1"
sUf(v "1" union convert ( @version
sUk(E "1" union JOIN ( select
sUo(E "1" union * ( select
sUon( "1" union * aname (
sUon1 "1" union * aname 1
sUonf "1" union * aname convert
sUons "1" union * aname "1"
sUs,( "1" union "1" , (
sUs,f "1" union "1" , convert
sUsc "1" union "1"  -- comment
sUso( "1" union "1" * (
sUso1 "1" union "1" * 1
sUsof "1" union "1" * convert
sUson "1" union "1" * aname
sUsos "1" union "1" * "1"
sUsov "1" union "1" * @version
sUv,( "1" union @version , (
sUv,f "1" union @version , convert
sUvc "1" union @version  -- comment
sUvo( "1" union @version * (
sUvof "1" union @version * convert
sUvos "1" union @version * "1"
sc "1"  -- comment
sf()1 "1" convert ( ) 1
sf()U "1" convert ( ) union
sf()f "1" convert ( ) convert
sf()k "1" convert ( ) JOIN
sf()n "1" convert ( ) aname
sf()o "1" convert ( ) *
sf()s "1" convert ( ) "1"
sf()v "1" convert ( ) @version
sf(1) "1" convert ( 1 )
sf(1n "1" convert ( 1 aname
sf(1o "1" convert ( 1 *
sf(E( "1" convert ( select (
sf(E1 "1" convert ( select 1
sf(Ef "1" convert ( select convert
sf(Ek "1" convert ( select JOIN
sf(En "1" convert ( select aname
sf(Es "1" convert ( select "1"
sf(Ev "1" convert ( select @version
sf(f( "1" convert ( convert (
sf(n) "1" convert ( aname )
sf(n, "1" convert ( aname ,
sf(no "1" convert ( aname *
sf(s) "1" convert ( "1" )
sf(so "1" convert ( "1" *
sf(v) "1" convert ( @version )
sf(vo "1" convert ( @version *
sk(1) "1" JOIN ( 1 )
sk(1o "1" JOIN ( 1 *
sk(f( "1" JOIN ( convert (
sk(n) "1" JOIN ( aname )
sk(no "1" JOIN ( aname *
sk(s) "1" JOIN ( "1" )
sk(so "1" JOIN ( "1" *
sk(v) "1" JOIN ( @version )
sk(vo "1" JOIN ( @version *
sk)&( "1" JOIN ) and (
sk)&1 "1" JOIN ) and 1
sk)&f "1" JOIN ) and convert
sk)&n "1" JOIN ) and aname
sk)&s "1" JOIN ) and "1"
sk)&v "1" JOIN ) and @version
sk);E "1" JOIN ) ; select
sk);T "1" JOIN ) ; DROP
sk)B( "1" JOIN ) group by (
sk)B1 "1" JOIN ) group by 1
sk)Bf "1" JOIN ) group by convert
sk)Bn "1" JOIN ) group by aname
sk)Bs "1" JOIN ) group by "1"
sk)Bv "1" JOIN ) group by @version
sk)E( "1" JOIN ) select (
sk)E1 "1" JOIN ) select 1
sk)Ef "1" JOIN ) select convert
sk)Ek "1" JOIN ) select JOIN
sk)En "1" JOIN ) select aname
sk)Es "1" JOIN ) select "1"
sk)Ev "1" JOIN ) select @version
sk)UE "1" JOIN ) union select
sk)f( "1" JOIN ) convert (
sk)o( "1" JOIN ) * (
sk)of "1" JOIN ) * convert
sk1 "1" JOIN 1
sk1&( "1" JOIN 1 and (
sk1&1 "1" JOIN 1 and 1
sk1&f "1" JOIN 1 and convert
sk1&n "1" JOIN 1 and aname
sk1&s "1" JOIN 1 and "1"
sk1&v "1" JOIN 1 and @version
sk1; "1" JOIN 1 ;
sk1;E "1" JOIN 1 ; select
sk1;T "1" JOIN 1 ; DROP
sk1;c "1" JOIN 1 ;  -- comment
sk1B( "1" JOIN 1 group by (
sk1B1 "1" JOIN 1 group by 1
sk1Bf "1" JOIN 1 group by convert
sk1Bn "1" JOIN 1 group by aname
sk1Bs "1" JOIN 1 group by "1"
sk1Bv "1" JOIN 1 group by @version
sk1E( "1" JOIN 1 select (
sk1E1 "1" JOIN 1 select 1
sk1Ef "1" JOIN 1 select convert
sk1Ek "1" JOIN 1 select JOIN
sk1En "1" JOIN 1 select aname
sk1Es "1" JOIN 1 select "1"
sk1Ev "1" JOIN 1 select @version
sk1U( "1" JOIN 1 union (
sk1UE "1" JOIN 1 union select
sk1c "1" JOIN 1  -- comment
sk1o( "1" JOIN 1 * (
sk1of "1" JOIN 1 * convert
sk1os "1" JOIN 1 * "1"
sk1ov "1" JOIN 1 * @version
skUE( "1" JOIN union select (
skUE1 "1" JOIN union select 1
skUEf "1" JOIN union select convert
skUEk "1" JOIN union select JOIN
skUEn "1" JOIN union select aname
skUEs "1" JOIN union select "1"
skUEv "1" JOIN union select @version
skf() "1" JOIN convert ( )
skf(1 "1" JOIN convert ( 1
skf(f "1" JOIN convert ( convert
skf(n "1" JOIN convert ( aname
skf(s "1" JOIN convert ( "1"
skf(v "1" JOIN convert ( @version
skn "1" JOIN aname
skn&( "1" JOIN aname and (
skn&1 "1" JOIN aname and 1
skn&f "1" JOIN aname and convert
skn&n "1" JOIN aname and aname
skn&s "1" JOIN aname and "1"
skn&v "1" JOIN aname and @version
skn; "1" JOIN aname ;
skn;E "1" JOIN aname ; select
skn;T "1" JOIN aname ; DROP
skn;c "1" JOIN aname ;  -- comment
sknB( "1" JOIN aname group by (
sknB1 "1" JOIN aname group by 1
sknBf "1" JOIN aname group by convert
sknBn "1" JOIN aname group by aname
sknBs "1" JOIN aname group by "1"
sknBv "1" JOIN aname group by @version
sknE( "1" JOIN aname select (
sknE1 "1" JOIN aname select 1
sknEf "1" JOIN aname select convert
sknEn "1" JOIN aname select aname
sknEs "1" JOIN aname select "1"
sknEv "1" JOIN aname select @version
sknU( "1" JOIN aname union (
sknUE "1" JOIN aname union select
sknc "1" JOIN aname  -- comment
sks "1" JOIN "1"
sks&( "1" JOIN "1" and (
sks&1 "1" JOIN "1" and 1
sks&f "1" JOIN "1" and convert
sks&n "1" JOIN "1" and aname
sks&s "1" JOIN "1" and "1"
sks&v "1" JOIN "1" and @version
sks; "1" JOIN "1" ;
sks;E "1" JOIN "1" ; select
sks;T "1" JOIN "1" ; DROP
sks;c "1" JOIN "1" ;  -- comment
sksB( "1" JOIN "1" group by (
sksB1 "1" JOIN "1" group by 1
sksBf "1" JOIN "1" group by convert
sksBn "1" JOIN "1" group by aname
sksBs "1" JOIN "1" group by "1"
sksBv "1" JOIN "1" group by @version
sksE( "1" JOIN "1" select (
sksE1 "1" JOIN "1" select 1
sksEf "1" JOIN "1" select convert
sksEk "1" JOIN "1" select JOIN
sksEn "1" JOIN "1" select aname
sksEs "1" JOIN "1" select "1"
sksEv "1" JOIN "1" select @version
sksU( "1" JOIN "1" union (
sksUE "1" JOIN "1" union select
sksc "1" JOIN "1"  -- comment
skso( "1" JOIN "1" * (
skso1 "1" JOIN "1" * 1
sksof "1" JOIN "1" * convert
skson "1" JOIN "1" * aname
sksos "1" JOIN "1" * "1"
sksov "1" JOIN "1" * @version
skv "1" JOIN @version
skv&( "1" JOIN @version and (
skv&1 "1" JOIN @version and 1
skv&f "1" JOIN @version and convert
skv&n "1" JOIN @version and aname
skv&s "1" JOIN @version and "1"
skv&v "1" JOIN @version and @version
skv; "1" JOIN @version ;
skv;E "1" JOIN @version ; select
skv;T "1" JOIN @version ; DROP
skv;c "1" JOIN @version ;  -- comment
skvB( "1" JOIN @version group by (
skvB1 "1" JOIN @version group by 1
skvBf "1" JOIN @version group by convert
skvBn "1" JOIN @version group by aname
skvBs "1" JOIN @version group by "1"
skvBv "1" JOIN @version group by @version
skvE( "1" JOIN @version select (
skvE1 "1" JOIN @version select 1
skvEf "1" JOIN @version select convert
skvEk "1" JOIN @version select JOIN
skvEn "1" JOIN @version select aname
skvEs "1" JOIN @version select "1"
skvEv "1" JOIN @version select @version
skvU( "1" JOIN @version union (
skvUE "1" JOIN @version union select
skvc "1" JOIN @version  -- comment
skvo( "1" JOIN @version * (
skvof "1" JOIN @version * convert
skvos "1" JOIN @version * "1"
so(1& "1" * ( 1 and
so(1) "1" * ( 1 )
so(1, "1" * ( 1 ,
so(1o "1" * ( 1 *
so(E( "1" * ( select (
so(E1 "1" * ( select 1
so(EE "1" * ( select select
so(Ef "1" * ( select convert
so(Ek "1" * ( select JOIN
so(En "1" * ( select aname
so(Eo "1" * ( select *
so(Es "1" * ( select "1"
so(Ev "1" * ( select @version
so(f( "1" * ( convert (
so(n& "1" * ( aname and
so(n) "1" * ( aname )
so(n, "1" * ( aname ,
so(no "1" * ( aname *
so(s& "1" * ( "1" and
so(s) "1" * ( "1" )
so(s, "1" * ( "1" ,
so(so "1" * ( "1" *
so(v& "1" * ( @version and
so(v) "1" * ( @version )
so(v, "1" * ( @version ,
so(vo "1" * ( @version *
so1&( "1" * 1 and (
so1&1 "1" * 1 and 1
so1&E "1" * 1 and select
so1&U "1" * 1 and union
so1&f "1" * 1 and convert
so1&k "1" * 1 and JOIN
so1&n "1" * 1 and aname
so1&s "1" * 1 and "1"
so1&v "1" * 1 and @version
so1(E "1" * 1 ( select
so1(U "1" * 1 ( union
so1)& "1" * 1 ) and
so1), "1" * 1 ) ,
so1); "1" * 1 ) ;
so1)B "1" * 1 ) group by
so1)E "1" * 1 ) select
so1)U "1" * 1 ) union
so1)c "1" * 1 )  -- comment
so1)f "1" * 1 ) convert
so1)k "1" * 1 ) JOIN
so1)o "1" * 1 ) *
so1,( "1" * 1 , (
so1,f "1" * 1 , convert
so1; "1" * 1 ;
so1;E "1" * 1 ; select
so1;T "1" * 1 ; DROP
so1;c "1" * 1 ;  -- comment
so1;n "1" * 1 ; aname
so1A( "1" * 1 COLLATE (
so1Af "1" * 1 COLLATE convert
so1As "1" * 1 COLLATE "1"
so1At "1" * 1 COLLATE binary
so1Av "1" * 1 COLLATE @version
so1B( "1" * 1 group by (
so1B1 "1" * 1 group by 1
so1BE "1" * 1 group by select
so1Bf "1" * 1 group by convert
so1Bn "1" * 1 group by aname
so1Bs "1" * 1 group by "1"
so1Bv "1" * 1 group by @version
so1E( "1" * 1 select (
so1E1 "1" * 1 select 1
so1EU "1" * 1 select union
so1Ef "1" * 1 select convert
so1Ek "1" * 1 select JOIN
so1En "1" * 1 select aname
so1Eo "1" * 1 select *
so1Es "1" * 1 select "1"
so1Ev "1" * 1 select @version
so1T( "1" * 1 DROP (
so1T1 "1" * 1 DROP 1
so1TE "1" * 1 DROP select
so1TT "1" * 1 DROP DROP
so1Tf "1" * 1 DROP convert
so1Tn "1" * 1 DROP aname
so1Ts "1" * 1 DROP "1"
so1Tv "1" * 1 DROP @version
so1U "1" * 1 union
so1U( "1" * 1 union (
so1U1 "1" * 1 union 1
so1U; "1" * 1 union ;
so1UE "1" * 1 union select
so1UT "1" * 1 union DROP
so1Uc "1" * 1 union  -- comment
so1Uf "1" * 1 union convert
so1Uk "1" * 1 union JOIN
so1Uo "1" * 1 union *
so1Us "1" * 1 union "1"
so1Uv "1" * 1 union @version
so1c "1" * 1  -- comment
so1f( "1" * 1 convert (
so1k( "1" * 1 JOIN (
so1k) "1" * 1 JOIN )
so1k1 "1" * 1 JOIN 1
so1kB "1" * 1 JOIN group by
so1kU "1" * 1 JOIN union
so1kf "1" * 1 JOIN convert
so1kn "1" * 1 JOIN aname
so1ks "1" * 1 JOIN "1"
so1kv "1" * 1 JOIN @version
so1n& "1" * 1 aname and
so1n( "1" * 1 aname (
so1n, "1" * 1 aname ,
so1nE "1" * 1 aname select
so1nU "1" * 1 aname union
so1sU "1" * 1 "1" union
so1sv "1" * 1 "1" @version
so1v( "1" * 1 @version (
so1vU "1" * 1 @version union
so1vf "1" * 1 @version convert
so1vo "1" * 1 @version *
so1vs "1" * 1 @version "1"
soU(E "1" * union ( select
soUEk "1" * union select JOIN
soUEn "1" * union select aname
sof() "1" * convert ( )
sof(1 "1" * convert ( 1
sof(E "1" * convert ( select
sof(f "1" * convert ( convert
sof(n "1" * convert ( aname
sof(s "1" * convert ( "1"
sof(v "1" * convert ( @version
sok&( "1" * JOIN and (
sok&1 "1" * JOIN and 1
sok&f "1" * JOIN and convert
sok&n "1" * JOIN and aname
sok&s "1" * JOIN and "1"
sok&v "1" * JOIN and @version
sok(1 "1" * JOIN ( 1
sok(f "1" * JOIN ( convert
sok(n "1" * JOIN ( aname
sok(s "1" * JOIN ( "1"
sok(v "1" * JOIN ( @version
sok1c "1" * JOIN 1  -- comment
sok1o "1" * JOIN 1 *
sokf( "1" * JOIN convert (
soknc "1" * JOIN aname  -- comment
soko( "1" * JOIN * (
soko1 "1" * JOIN * 1
sokof "1" * JOIN * convert
sokon "1" * JOIN * aname
sokos "1" * JOIN * "1"
sokov "1" * JOIN * @version
soksc "1" * JOIN "1"  -- comment
sokso "1" * JOIN "1" *
sokvc "1" * JOIN @version  -- comment
sokvo "1" * JOIN @version *
son&( "1" * aname and (
son&1 "1" * aname and 1
son&E "1" * aname and select
son&U "1" * aname and union
son&f "1" * aname and convert
son&k "1" * aname and JOIN
son&n "1" * aname and aname
son&s "1" * aname and "1"
son&v "1" * aname and @version
son(1 "1" * aname ( 1
son(E "1" * aname ( select
son(U "1" * aname ( union
son(f "1" * aname ( convert
son(s "1" * aname ( "1"
son(v "1" * aname ( @version
son)& "1" * aname ) and
son), "1" * aname ) ,
son); "1" * aname ) ;
son)B "1" * aname ) group by
son)E "1" * aname ) select
son)U "1" * aname ) union
son)c "1" * aname )  -- comment
son)f "1" * aname ) convert
son)k "1" * aname ) JOIN
son)o "1" * aname ) *
son,( "1" * aname , (
son,f "1" * aname , convert
son1( "1" * aname 1 (
son1U "1" * aname 1 union
son1o "1" * aname 1 *
son1v "1" * aname 1 @version
son; "1" * aname ;
son;E "1" * aname ; select
son;T "1" * aname ; DROP
son;c "1" * aname ;  -- comment
son;n "1" * aname ; aname
sonA( "1" * aname COLLATE (
sonAf "1" * aname COLLATE convert
sonAs "1" * aname COLLATE "1"
sonAt "1" * aname COLLATE binary
sonAv "1" * aname COLLATE @version
sonB( "1" * aname group by (
sonB1 "1" * aname group by 1
sonBE "1" * aname group by select
sonBf "1" * aname group by convert
sonBn "1" * aname group by aname
sonBs "1" * aname group by "1"
sonBv "1" * aname group by @version
sonE( "1" * aname select (
sonE1 "1" * aname select 1
sonEU "1" * aname select union
sonEf "1" * aname select convert
sonEn "1" * aname select aname
sonEo "1" * aname select *
sonEs "1" * aname select "1"
sonEv "1" * aname select @version
sonT( "1" * aname DROP (
sonT1 "1" * aname DROP 1
sonTE "1" * aname DROP select
sonTT "1" * aname DROP DROP
sonTf "1" * aname DROP convert
sonTn "1" * aname DROP aname
sonTs "1" * aname DROP "1"
sonTv "1" * aname DROP @version
sonU "1" * aname union
sonU( "1" * aname union (
sonU1 "1" * aname union 1
sonU; "1" * aname union ;
sonUE "1" * aname union select
sonUT "1" * aname union DROP
sonUc "1" * aname union  -- comment
sonUf "1" * aname union convert
sonUk "1" * aname union JOIN
sonUo "1" * aname union *
sonUs "1" * aname union "1"
sonUv "1" * aname union @version
sonf( "1" * aname convert (
sonk( "1" * aname JOIN (
sonk) "1" * aname JOIN )
sonk1 "1" * aname JOIN 1
sonkB "1" * aname JOIN group by
sonkU "1" * aname JOIN union
sonkf "1" * aname JOIN convert
sonks "1" * aname JOIN "1"
sonkv "1" * aname JOIN @version
sonsU "1" * aname "1" union
sos "1" * "1"
sos&( "1" * "1" and (
sos&1 "1" * "1" and 1
sos&E "1" * "1" and select
sos&U "1" * "1" and union
sos&f "1" * "1" and convert
sos&k "1" * "1" and JOIN
sos&n "1" * "1" and aname
sos&s "1" * "1" and "1"
sos&v "1" * "1" and @version
sos(E "1" * "1" ( select
sos(U "1" * "1" ( union
sos)& "1" * "1" ) and
sos), "1" * "1" ) ,
sos); "1" * "1" ) ;
sos)B "1" * "1" ) group by
sos)E "1" * "1" ) select
sos)U "1" * "1" ) union
sos)c "1" * "1" )  -- comment
sos)f "1" * "1" ) convert
sos)k "1" * "1" ) JOIN
sos)o "1" * "1" ) *
sos,( "1" * "1" , (
sos,f "1" * "1" , convert
sos1( "1" * "1" 1 (
sos1U "1" * "1" 1 union
sos1f "1" * "1" 1 convert
sos1n "1" * "1" 1 aname
sos1s "1" * "1" 1 "1"
sos1v "1" * "1" 1 @version
sos; "1" * "1" ;
sos;E "1" * "1" ; select
sos;T "1" * "1" ; DROP
sos;c "1" * "1" ;  -- comment
sos;n "1" * "1" ; aname
sosA( "1" * "1" COLLATE (
sosAf "1" * "1" COLLATE convert
sosAs "1" * "1" COLLATE "1"
sosAt "1" * "1" COLLATE binary
sosAv "1" * "1" COLLATE @version
sosB( "1" * "1" group by (
sosB1 "1" * "1" group by 1
sosBE "1" * "1" group by select
sosBf "1" * "1" group by convert
sosBn "1" * "1" group by aname
sosBs "1" * "1" group by "1"
sosBv "1" * "1" group by @version
sosE( "1" * "1" select (
sosE1 "1" * "1" select 1
sosEU "1" * "1" select union
sosEf "1" * "1" select convert
sosEk "1" * "1" select JOIN
sosEn "1" * "1" select aname
sosEo "1" * "1" select *
sosEs "1" * "1" select "1"
sosEv "1" * "1" select @version
sosT( "1" * "1" DROP (
sosT1 "1" * "1" DROP 1
sosTE "1" * "1" DROP select
sosTT "1" * "1" DROP DROP
sosTf "1" * "1" DROP convert
sosTn "1" * "1" DROP aname
sosTs "1" * "1" DROP "1"
sosTv "1" * "1" DROP @version
sosU "1" * "1" union
sosU( "1" * "1" union (
sosU1 "1" * "1" union 1
sosU; "1" * "1" union ;
sosUE "1" * "1" union select
sosUT "1" * "1" union DROP
sosUc "1" * "1" union  -- comment
sosUf "1" * "1" union convert
sosUk "1" * "1" union JOIN
sosUo "1" * "1" union *
sosUs "1" * "1" union "1"
sosUv "1" * "1" union @version
sosc "1" * "1"  -- comment
sosf( "1" * "1" convert (
sosk( "1" * "1" JOIN (
sosk) "1" * "1" JOIN )
sosk1 "1" * "1" JOIN 1
soskB "1" * "1" JOIN group by
soskU "1" * "1" JOIN union
soskf "1" * "1" JOIN convert
soskn "1" * "1" JOIN aname
sosks "1" * "1" JOIN "1"
soskv "1" * "1" JOIN @version
sosv( "1" * "1" @version (
sosvU "1" * "1" @version union
sosvf "1" * "1" @version convert
sosvo "1" * "1" @version *
sosvs "1" * "1" @version "1"
sov "1" * @version
sov&( "1" * @version and (
sov&1 "1" * @version and 1
sov&E "1" * @version and select
sov&U "1" * @version and union
sov&f "1" * @version and convert
sov&k "1" * @version and JOIN
sov&n "1" * @version and aname
sov&s "1" * @version and "1"
sov&v "1" * @version and @version
sov(E "1" * @version ( select
sov(U "1" * @version ( union
sov)& "1" * @version ) and
sov), "1" * @version ) ,
sov); "1" * @version ) ;
sov)B "1" * @version ) group by
sov)E "1" * @version ) select
sov)U "1" * @version ) union
sov)c "1" * @version )  -- comment
sov)f "1" * @version ) convert
sov)k "1" * @version ) JOIN
sov)o "1" * @version ) *
sov,( "1" * @version , (
sov,f "1" * @version , convert
sov; "1" * @version ;
sov;E "1" * @version ; select
sov;T "1" * @version ; DROP
sov;c "1" * @version ;  -- comment
sov;n "1" * @version ; aname
sovA( "1" * @version COLLATE (
sovAf "1" * @version COLLATE convert
sovAs "1" * @version COLLATE "1"
sovAt "1" * @version COLLATE binary
sovAv "1" * @version COLLATE @version
sovB( "1" * @version group by (
sovB1 "1" * @version group by 1
sovBE "1" * @version group by select
sovBf "1" * @version group by convert
sovBn "1" * @version group by aname
sovBs "1" * @version group by "1"
sovBv "1" * @version group by @version
sovE( "1" * @version select (
sovE1 "1" * @version select 1
sovEU "1" * @version select union
sovEf "1" * @version select convert
sovEk "1" * @version select JOIN
sovEn "1" * @version select aname
sovEo "1" * @version select *
sovEs "1" * @version select "1"
sovEv "1" * @version select @version
sovT( "1" * @version DROP (
sovT1 "1" * @version DROP 1
sovTE "1" * @version DROP select
sovTT "1" * @version DROP DROP
sovTf "1" * @version DROP convert
sovTn "1" * @version DROP aname
sovTs "1" * @version DROP "1"
sovTv "1" * @version DROP @version
sovU "1" * @version union
sovU( "1" * @version union (
sovU1 "1" * @version union 1
sovU; "1" * @version union ;
sovUE "1" * @version union select
sovUT "1" * @version union DROP
sovUc "1" * @version union  -- comment
sovUf "1" * @version union convert
sovUk "1" * @version union JOIN
sovUo "1" * @version union *
sovUs "1" * @version union "1"
sovUv "1" * @version union @version
sovc "1" * @version  -- comment
sovf( "1" * @version convert (
sovk( "1" * @version JOIN (
sovk) "1" * @version JOIN )
sovk1 "1" * @version JOIN 1
sovkB "1" * @version JOIN group by
sovkU "1" * @version JOIN union
sovkf "1" * @version JOIN convert
sovkn "1" * @version JOIN aname
sovks "1" * @version JOIN "1"
sovkv "1" * @version JOIN @version
sovo( "1" * @version * (
sovoU "1" * @version * union
sovof "1" * @version * convert
sovok "1" * @version * JOIN
sovos "1" * @version * "1"
sovs( "1" * @version "1" (
sovs1 "1" * @version "1" 1
sovsU "1" * @version "1" union
sovsf "1" * @version "1" convert
sovso "1" * @version "1" *
sovsv "1" * @version "1" @version
svUE "1" @version union select
svUE; "1" @version union select ;
svUEc "1" @version union select  -- comment
svUEk "1" @version union select JOIN
svf() "1" @version convert ( )
svf(1 "1" @version convert ( 1
svf(f "1" @version convert ( convert
svf(n "1" @version convert ( aname
svf(s "1" @version convert ( "1"
svf(v "1" @version convert ( @version
svo(1 "1" @version * ( 1
svo(f "1" @version * ( convert
svo(n "1" @version * ( aname
svo(s "1" @version * ( "1"
svo(v "1" @version * ( @version
svof( "1" @version * convert (
svos( "1" @version * "1" (
svos1 "1" @version * "1" 1
svosU "1" @version * "1" union
svosf "1" @version * "1" convert
svosv "1" @version * "1" @version
svs; "1" @version "1" ;
svs;c "1" @version "1" ;  -- comment
svsc "1" @version "1"  -- comment
svso( "1" @version "1" * (
svso1 "1" @version "1" * 1
svsof "1" @version "1" * convert
svson "1" @version "1" * aname
svsos "1" @version "1" * "1"
svsov "1" @version "1" * @version
v&(1& @version and ( 1 and
v&(1) @version and ( 1 )
v&(1, @version and ( 1 ,
v&(1o @version and ( 1 *
v&(E( @version and ( select (
v&(E1 @version and ( select 1
v&(Ef @version and ( select convert
v&(Ek @version and ( select JOIN
v&(En @version and ( select aname
v&(Eo @version and ( select *
v&(Es @version and ( select "1"
v&(Ev @version and ( select @version
v&(f( @version and ( convert (
v&(n& @version and ( aname and
v&(n) @version and ( aname )
v&(n, @version and ( aname ,
v&(no @version and ( aname *
v&(s& @version and ( "1" and
v&(s) @version and ( "1" )
v&(s, @version and ( "1" ,
v&(so @version and ( "1" *
v&(v& @version and ( @version and
v&(v) @version and ( @version )
v&(v, @version and ( @version ,
v&(vo @version and ( @version *
v&1 @version and 1
v&1&( @version and 1 and (
v&1&1 @version and 1 and 1
v&1&f @version and 1 and convert
v&1&n @version and 1 and aname
v&1&s @version and 1 and "1"
v&1&v @version and 1 and @version
v&1)& @version and 1 ) and
v&1)U @version and 1 ) union
v&1)c @version and 1 )  -- comment
v&1)o @version and 1 ) *
v&1; @version and 1 ;
v&1;E @version and 1 ; select
v&1;T @version and 1 ; DROP
v&1;c @version and 1 ;  -- comment
v&1B( @version and 1 group by (
v&1B1 @version and 1 group by 1
v&1Bf @version and 1 group by convert
v&1Bn @version and 1 group by aname
v&1Bs @version and 1 group by "1"
v&1Bv @version and 1 group by @version
v&1Ek @version and 1 select JOIN
v&1En @version and 1 select aname
v&1Tn @version and 1 DROP aname
v&1U @version and 1 union
v&1U( @version and 1 union (
v&1U; @version and 1 union ;
v&1UE @version and 1 union select
v&1Uc @version and 1 union  -- comment
v&1c @version and 1  -- comment
v&1f( @version and 1 convert (
v&1k( @version and 1 JOIN (
v&1k1 @version and 1 JOIN 1
v&1kf @version and 1 JOIN convert
v&1kn @version and 1 JOIN aname
v&1ks @version and 1 JOIN "1"
v&1kv @version and 1 JOIN @version
v&1o( @version and 1 * (
v&1of @version and 1 * convert
v&1os @version and 1 * "1"
v&1ov @version and 1 * @version
v&E(1 @version and select ( 1
v&E(f @version and select ( convert
v&E(n @version and select ( aname
v&E(o @version and select ( *
v&E(s @version and select ( "1"
v&E(v @version and select ( @version
v&E1 @version and select 1
v&E1; @version and select 1 ;
v&E1c @version and select 1  -- comment
v&E1k @version and select 1 JOIN
v&E1o @version and select 1 *
v&Ef( @version and select convert (
v&Ek( @version and select JOIN (
v&Ek1 @version and select JOIN 1
v&Ekf @version and select JOIN convert
v&Ekn @version and select JOIN aname
v&Eks @version and select JOIN "1"
v&Ekv @version and select JOIN @version
v&En @version and select aname
v&En; @version and select aname ;
v&Enc @version and select aname  -- comment
v&Enk @version and select aname JOIN
v&Eno @version and select aname *
v&Es @version and select "1"
v&Es; @version and select "1" ;
v&Esc @version and select "1"  -- comment
v&Esk @version and select "1" JOIN
v&Eso @version and select "1" *
v&Ev @version and select @version
v&Ev; @version and select @version ;
v&Evc @version and select @version  -- comment
v&Evk @version and select @version JOIN
v&Evo @version and select @version *
v&f() @version and convert ( )
v&f(1 @version and convert ( 1
v&f(E @version and convert ( select
v&f(f @version and convert ( convert
v&f(n @version and convert ( aname
v&f(s @version and convert ( "1"
v&f(v @version and convert ( @version
v&k&( @version and JOIN and (
v&k&1 @version and JOIN and 1
v&k&f @version and JOIN and convert
v&k&n @version and JOIN and aname
v&k&s @version and JOIN and "1"
v&k&v @version and JOIN and @version
v&k(1 @version and JOIN ( 1
v&k(f @version and JOIN ( convert
v&k(n @version and JOIN ( aname
v&k(s @version and JOIN ( "1"
v&k(v @version and JOIN ( @version
v&k1o @version and JOIN 1 *
v&kc @version and JOIN  -- comment
v&kf( @version and JOIN convert (
v&knk @version and JOIN aname JOIN
v&ko( @version and JOIN * (
v&ko1 @version and JOIN * 1
v&kof @version and JOIN * convert
v&kok @version and JOIN * JOIN
v&kon @version and JOIN * aname
v&kos @version and JOIN * "1"
v&kov @version and JOIN * @version
v&kso @version and JOIN "1" *
v&kvo @version and JOIN @version *
v&n @version and aname
v&n&( @version and aname and (
v&n&1 @version and aname and 1
v&n&f @version and aname and convert
v&n&n @version and aname and aname
v&n&s @version and aname and "1"
v&n&v @version and aname and @version
v&n)& @version and aname ) and
v&n)U @version and aname ) union
v&n)c @version and aname )  -- comment
v&n)o @version and aname ) *
v&n; @version and aname ;
v&n;E @version and aname ; select
v&n;T @version and aname ; DROP
v&n;c @version and aname ;  -- comment
v&nB( @version and aname group by (
v&nB1 @version and aname group by 1
v&nBf @version and aname group by convert
v&nBn @version and aname group by aname
v&nBs @version and aname group by "1"
v&nBv @version and aname group by @version
v&nEn @version and aname select aname
v&nTn @version and aname DROP aname
v&nU @version and aname union
v&nU( @version and aname union (
v&nU; @version and aname union ;
v&nUE @version and aname union select
v&nUc @version and aname union  -- comment
v&nc @version and aname  -- comment
v&nf( @version and aname convert (
v&nk( @version and aname JOIN (
v&nk1 @version and aname JOIN 1
v&nkf @version and aname JOIN convert
v&nkn @version and aname JOIN aname
v&nks @version and aname JOIN "1"
v&nkv @version and aname JOIN @version
v&no( @version and aname * (
v&nof @version and aname * convert
v&nos @version and aname * "1"
v&nov @version and aname * @version
v&s @version and "1"
v&s&( @version and "1" and (
v&s&1 @version and "1" and 1
v&s&f @version and "1" and convert
v&s&n @version and "1" and aname
v&s&s @version and "1" and "1"
v&s&v @version and "1" and @version
v&s)& @version and "1" ) and
v&s)U @version and "1" ) union
v&s)c @version and "1" )  -- comment
v&s)o @version and "1" ) *
v&s1 @version and "1" 1
v&s1; @version and "1" 1 ;
v&s1c @version and "1" 1  -- comment
v&s; @version and "1" ;
v&s;E @version and "1" ; select
v&s;T @version and "1" ; DROP
v&s;c @version and "1" ;  -- comment
v&sB( @version and "1" group by (
v&sB1 @version and "1" group by 1
v&sBf @version and "1" group by convert
v&sBn @version and "1" group by aname
v&sBs @version and "1" group by "1"
v&sBv @version and "1" group by @version
v&sEk @version and "1" select JOIN
v&sEn @version and "1" select aname
v&sTn @version and "1" DROP aname
v&sU @version and "1" union
v&sU( @version and "1" union (
v&sU; @version and "1" union ;
v&sUE @version and "1" union select
v&sUc @version and "1" union  -- comment
v&sc @version and "1"  -- comment
v&sf( @version and "1" convert (
v&sk( @version and "1" JOIN (
v&sk1 @version and "1" JOIN 1
v&skf @version and "1" JOIN convert
v&skn @version and "1" JOIN aname
v&sks @version and "1" JOIN "1"
v&skv @version and "1" JOIN @version
v&so( @version and "1" * (
v&so1 @version and "1" * 1
v&sof @version and "1" * convert
v&son @version and "1" * aname
v&sos @version and "1" * "1"
v&sov @version and "1" * @version
v&sv @version and "1" @version
v&sv; @version and "1" @version ;
v&svc @version and "1" @version  -- comment
v&svo @version and "1" @version *
v&v @version and @version
v&v&( @version and @version and (
v&v&1 @version and @version and 1
v&v&f @version and @version and convert
v&v&n @version and @version and aname
v&v&s @version and @version and "1"
v&v&v @version and @version and @version
v&v)& @version and @version ) and
v&v)U @version and @version ) union
v&v)c @version and @version )  -- comment
v&v)o @version and @version ) *
v&v; @version and @version ;
v&v;E @version and @version ; select
v&v;T @version and @version ; DROP
v&v;c @version and @version ;  -- comment
v&vB( @version and @version group by (
v&vB1 @version and @version group by 1
v&vBf @version and @version group by convert
v&vBn @version and @version group by aname
v&vBs @version and @version group by "1"
v&vBv @version and @version group by @version
v&vEk @version and @version select JOIN
v&vEn @version and @version select aname
v&vTn @version and @version DROP aname
v&vU @version and @version union
v&vU( @version and @version union (
v&vU; @version and @version union ;
v&vUE @version and @version union select
v&vUc @version and @version union  -- comment
v&vc @version and @version  -- comment
v&vf( @version and @version convert (
v&vk( @version and @version JOIN (
v&vk1 @version and @version JOIN 1
v&vkf @version and @version JOIN convert
v&vkn @version and @version JOIN aname
v&vks @version and @version JOIN "1"
v&vkv @version and @version JOIN @version
v&vo( @version and @version * (
v&vof @version and @version * convert
v&vos @version and @version * "1"
v&vs @version and @version "1"
v&vs; @version and @version "1" ;
v&vsc @version and @version "1"  -- comment
v&vso @version and @version "1" *
v(Ef( @version ( select convert (
v(Ekf @version ( select JOIN convert
v(Ekn @version ( select JOIN aname
v(Enk @version ( select aname JOIN
v(U(E @version ( union ( select
v)&(1 @version ) and ( 1
v)&(E @version ) and ( select
v)&(f @version ) and ( convert
v)&(n @version ) and ( aname
v)&(s @version ) and ( "1"
v)&(v @version ) and ( @version
v)&1 @version ) and 1
v)&1& @version ) and 1 and
v)&1) @version ) and 1 )
v)&1; @version ) and 1 ;
v)&1B @version ) and 1 group by
v)&1U @version ) and 1 union
v)&1c @version ) and 1  -- comment
v)&1f @version ) and 1 convert
v)&1o @version ) and 1 *
v)&f( @version ) and convert (
v)&n @version ) and aname
v)&n& @version ) and aname and
v)&n) @version ) and aname )
v)&n; @version ) and aname ;
v)&nB @version ) and aname group by
v)&nU @version ) and aname union
v)&nc @version ) and aname  -- comment
v)&nf @version ) and aname convert
v)&no @version ) and aname *
v)&s @version ) and "1"
v)&s& @version ) and "1" and
v)&s) @version ) and "1" )
v)&s; @version ) and "1" ;
v)&sB @version ) and "1" group by
v)&sU @version ) and "1" union
v)&sc @version ) and "1"  -- comment
v)&sf @version ) and "1" convert
v)&so @version ) and "1" *
v)&v @version ) and @version
v)&v& @version ) and @version and
v)&v) @version ) and @version )
v)&v; @version ) and @version ;
v)&vB @version ) and @version group by
v)&vU @version ) and @version union
v)&vc @version ) and @version  -- comment
v)&vf @version ) and @version convert
v)&vo @version ) and @version *
v),(1 @version ) , ( 1
v),(f @version ) , ( convert
v),(n @version ) , ( aname
v),(s @version ) , ( "1"
v),(v @version ) , ( @version
v);E( @version ) ; select (
v);E1 @version ) ; select 1
v);Ef @version ) ; select convert
v);Ek @version ) ; select JOIN
v);En @version ) ; select aname
v);Eo @version ) ; select *
v);Es @version ) ; select "1"
v);Ev @version ) ; select @version
v);T( @version ) ; DROP (
v);T1 @version ) ; DROP 1
v);Tf @version ) ; DROP convert
v);Tk @version ) ; DROP JOIN
v);Tn @version ) ; DROP aname
v);To @version ) ; DROP *
v);Ts @version ) ; DROP "1"
v);Tv @version ) ; DROP @version
v)B(1 @version ) group by ( 1
v)B(f @version ) group by ( convert
v)B(n @version ) group by ( aname
v)B(s @version ) group by ( "1"
v)B(v @version ) group by ( @version
v)B1 @version ) group by 1
v)B1& @version ) group by 1 and
v)B1; @version ) group by 1 ;
v)B1U @version ) group by 1 union
v)B1c @version ) group by 1  -- comment
v)B1k @version ) group by 1 JOIN
v)B1n @version ) group by 1 aname
v)B1o @version ) group by 1 *
v)Bf( @version ) group by convert (
v)Bn @version ) group by aname
v)Bn& @version ) group by aname and
v)Bn; @version ) group by aname ;
v)BnU @version ) group by aname union
v)Bnc @version ) group by aname  -- comment
v)Bnk @version ) group by aname JOIN
v)Bno @version ) group by aname *
v)Bs @version ) group by "1"
v)Bs& @version ) group by "1" and
v)Bs; @version ) group by "1" ;
v)BsU @version ) group by "1" union
v)Bsc @version ) group by "1"  -- comment
v)Bsk @version ) group by "1" JOIN
v)Bso @version ) group by "1" *
v)Bv @version ) group by @version
v)Bv& @version ) group by @version and
v)Bv; @version ) group by @version ;
v)BvU @version ) group by @version union
v)Bvc @version ) group by @version  -- comment
v)Bvk @version ) group by @version JOIN
v)Bvo @version ) group by @version *
v)E(1 @version ) select ( 1
v)E(f @version ) select ( convert
v)E(n @version ) select ( aname
v)E(s @version ) select ( "1"
v)E(v @version ) select ( @version
v)E1c @version ) select 1  -- comment
v)E1o @version ) select 1 *
v)Ef( @version ) select convert (
v)Ek( @version ) select JOIN (
v)Ek1 @version ) select JOIN 1
v)Ekf @version ) select JOIN convert
v)Ekn @version ) select JOIN aname
v)Eks @version ) select JOIN "1"
v)Ekv @version ) select JOIN @version
v)Enc @version ) select aname  -- comment
v)Eno @version ) select aname *
v)Esc @version ) select "1"  -- comment
v)Eso @version ) select "1" *
v)Evc @version ) select @version  -- comment
v)Evo @version ) select @version *
v)U(E @version ) union ( select
v)UE( @version ) union select (
v)UE1 @version ) union select 1
v)UEf @version ) union select convert
v)UEk @version ) union select JOIN
v)UEn @version ) union select aname
v)UEs @version ) union select "1"
v)UEv @version ) union select @version
v)c @version )  -- comment
v)f(f @version ) convert ( convert
v)k(1 @version ) JOIN ( 1
v)k(f @version ) JOIN ( convert
v)k(n @version ) JOIN ( aname
v)k(s @version ) JOIN ( "1"
v)k(v @version ) JOIN ( @version
v)k1& @version ) JOIN 1 and
v)k1; @version ) JOIN 1 ;
v)k1B @version ) JOIN 1 group by
v)k1E @version ) JOIN 1 select
v)k1U @version ) JOIN 1 union
v)k1o @version ) JOIN 1 *
v)kB( @version ) JOIN group by (
v)kB1 @version ) JOIN group by 1
v)kBf @version ) JOIN group by convert
v)kBn @version ) JOIN group by aname
v)kBs @version ) JOIN group by "1"
v)kBv @version ) JOIN group by @version
v)kUE @version ) JOIN union select
v)kf( @version ) JOIN convert (
v)kn& @version ) JOIN aname and
v)kn; @version ) JOIN aname ;
v)knB @version ) JOIN aname group by
v)knE @version ) JOIN aname select
v)knU @version ) JOIN aname union
v)knc @version ) JOIN aname  -- comment
v)knk @version ) JOIN aname JOIN
v)ks& @version ) JOIN "1" and
v)ks; @version ) JOIN "1" ;
v)ksB @version ) JOIN "1" group by
v)ksE @version ) JOIN "1" select
v)ksU @version ) JOIN "1" union
v)kso @version ) JOIN "1" *
v)kv& @version ) JOIN @version and
v)kv; @version ) JOIN @version ;
v)kvB @version ) JOIN @version group by
v)kvE @version ) JOIN @version select
v)kvU @version ) JOIN @version union
v)kvo @version ) JOIN @version *
v)o(1 @version ) * ( 1
v)o(E @version ) * ( select
v)o(f @version ) * ( convert
v)o(n @version ) * ( aname
v)o(s @version ) * ( "1"
v)o(v @version ) * ( @version
v)o1 @version ) * 1
v)o1& @version ) * 1 and
v)o1) @version ) * 1 )
v)o1; @version ) * 1 ;
v)o1B @version ) * 1 group by
v)o1U @version ) * 1 union
v)o1c @version ) * 1  -- comment
v)o1k @version ) * 1 JOIN
v)of( @version ) * convert (
v)on @version ) * aname
v)on& @version ) * aname and
v)on) @version ) * aname )
v)on; @version ) * aname ;
v)onB @version ) * aname group by
v)onU @version ) * aname union
v)onc @version ) * aname  -- comment
v)onk @version ) * aname JOIN
v)os @version ) * "1"
v)os& @version ) * "1" and
v)os) @version ) * "1" )
v)os; @version ) * "1" ;
v)osB @version ) * "1" group by
v)osU @version ) * "1" union
v)osc @version ) * "1"  -- comment
v)osk @version ) * "1" JOIN
v)ov @version ) * @version
v)ov& @version ) * @version and
v)ov) @version ) * @version )
v)ov; @version ) * @version ;
v)ovB @version ) * @version group by
v)ovU @version ) * @version union
v)ovc @version ) * @version  -- comment
v)ovk @version ) * @version JOIN
v)ovo @version ) * @version *
v,(1) @version , ( 1 )
v,(1o @version , ( 1 *
v,(E( @version , ( select (
v,(E1 @version , ( select 1
v,(Ef @version , ( select convert
v,(Ek @version , ( select JOIN
v,(En @version , ( select aname
v,(Es @version , ( select "1"
v,(Ev @version , ( select @version
v,(f( @version , ( convert (
v,(n) @version , ( aname )
v,(no @version , ( aname *
v,(s) @version , ( "1" )
v,(so @version , ( "1" *
v,(v) @version , ( @version )
v,(vo @version , ( @version *
v,f() @version , convert ( )
v,f(1 @version , convert ( 1
v,f(f @version , convert ( convert
v,f(n @version , convert ( aname
v,f(s @version , convert ( "1"
v,f(v @version , convert ( @version
v;E(1 @version ; select ( 1
v;E(E @version ; select ( select
v;E(f @version ; select ( convert
v;E(n @version ; select ( aname
v;E(s @version ; select ( "1"
v;E(v @version ; select ( @version
v;E1, @version ; select 1 ,
v;E1; @version ; select 1 ;
v;E1T @version ; select 1 DROP
v;E1c @version ; select 1  -- comment
v;E1k @version ; select 1 JOIN
v;E1o @version ; select 1 *
v;Ef( @version ; select convert (
v;Ek( @version ; select JOIN (
v;Ek1 @version ; select JOIN 1
v;Ekf @version ; select JOIN convert
v;Ekn @version ; select JOIN aname
v;Eko @version ; select JOIN *
v;Eks @version ; select JOIN "1"
v;Ekv @version ; select JOIN @version
v;En, @version ; select aname ,
v;En; @version ; select aname ;
v;EnE @version ; select aname select
v;EnT @version ; select aname DROP
v;Enc @version ; select aname  -- comment
v;Enk @version ; select aname JOIN
v;Eno @version ; select aname *
v;Es, @version ; select "1" ,
v;Es; @version ; select "1" ;
v;EsT @version ; select "1" DROP
v;Esc @version ; select "1"  -- comment
v;Esk @version ; select "1" JOIN
v;Eso @version ; select "1" *
v;Ev, @version ; select @version ,
v;Ev; @version ; select @version ;
v;EvT @version ; select @version DROP
v;Evc @version ; select @version  -- comment
v;Evk @version ; select @version JOIN
v;Evo @version ; select @version *
v;T(1 @version ; DROP ( 1
v;T(E @version ; DROP ( select
v;T(c @version ; DROP (  -- comment
v;T(f @version ; DROP ( convert
v;T(n @version ; DROP ( aname
v;T(s @version ; DROP ( "1"
v;T(v @version ; DROP ( @version
v;T1( @version ; DROP 1 (
v;T1, @version ; DROP 1 ,
v;T1; @version ; DROP 1 ;
v;T1T @version ; DROP 1 DROP
v;T1c @version ; DROP 1  -- comment
v;T1f @version ; DROP 1 convert
v;T1k @version ; DROP 1 JOIN
v;T1o @version ; DROP 1 *
v;T; @version ; DROP ;
v;T;c @version ; DROP ;  -- comment
v;TTn @version ; DROP DROP aname
v;Tf( @version ; DROP convert (
v;Tk( @version ; DROP JOIN (
v;Tk1 @version ; DROP JOIN 1
v;Tkf @version ; DROP JOIN convert
v;Tkk @version ; DROP JOIN JOIN
v;Tkn @version ; DROP JOIN aname
v;Tko @version ; DROP JOIN *
v;Tks @version ; DROP JOIN "1"
v;Tkv @version ; DROP JOIN @version
v;Tn( @version ; DROP aname (
v;Tn, @version ; DROP aname ,
v;Tn1 @version ; DROP aname 1
v;Tn; @version ; DROP aname ;
v;TnE @version ; DROP aname select
v;TnT @version ; DROP aname DROP
v;Tnc @version ; DROP aname  -- comment
v;Tnf @version ; DROP aname convert
v;Tnk @version ; DROP aname JOIN
v;Tnn @version ; DROP aname aname
v;Tno @version ; DROP aname *
v;Tns @version ; DROP aname "1"
v;Tnv @version ; DROP aname @version
v;To( @version ; DROP * (
v;Ts( @version ; DROP "1" (
v;Ts, @version ; DROP "1" ,
v;Ts; @version ; DROP "1" ;
v;TsT @version ; DROP "1" DROP
v;Tsc @version ; DROP "1"  -- comment
v;Tsf @version ; DROP "1" convert
v;Tsk @version ; DROP "1" JOIN
v;Tso @version ; DROP "1" *
v;Tv( @version ; DROP @version (
v;Tv, @version ; DROP @version ,
v;Tv; @version ; DROP @version ;
v;TvT @version ; DROP @version DROP
v;Tvc @version ; DROP @version  -- comment
v;Tvf @version ; DROP @version convert
v;Tvk @version ; DROP @version JOIN
v;Tvo @version ; DROP @version *
v;n:T @version ; aname : DROP
vA(f( @version COLLATE ( convert (
vA(n) @version COLLATE ( aname )
vA(no @version COLLATE ( aname *
vA(s) @version COLLATE ( "1" )
vA(so @version COLLATE ( "1" *
vA(v) @version COLLATE ( @version )
vA(vo @version COLLATE ( @version *
vAf() @version COLLATE convert ( )
vAf(1 @version COLLATE convert ( 1
vAf(f @version COLLATE convert ( convert
vAf(n @version COLLATE convert ( aname
vAf(s @version COLLATE convert ( "1"
vAf(v @version COLLATE convert ( @version
vAsUE @version COLLATE "1" union select
vAso( @version COLLATE "1" * (
vAso1 @version COLLATE "1" * 1
vAsof @version COLLATE "1" * convert
vAson @version COLLATE "1" * aname
vAsos @version COLLATE "1" * "1"
vAsov @version COLLATE "1" * @version
vAtUE @version COLLATE binary union select
vAto( @version COLLATE binary * (
vAto1 @version COLLATE binary * 1
vAtof @version COLLATE binary * convert
vAton @version COLLATE binary * aname
vAtos @version COLLATE binary * "1"
vAtov @version COLLATE binary * @version
vAvUE @version COLLATE @version union select
vAvo( @version COLLATE @version * (
vAvof @version COLLATE @version * convert
vAvos @version COLLATE @version * "1"
vB(1) @version group by ( 1 )
vB(1o @version group by ( 1 *
vB(f( @version group by ( convert (
vB(no @version group by ( aname *
vB(s) @version group by ( "1" )
vB(so @version group by ( "1" *
vB(v) @version group by ( @version )
vB(vo @version group by ( @version *
vB1 @version group by 1
vB1&( @version group by 1 and (
vB1&1 @version group by 1 and 1
vB1&f @version group by 1 and convert
vB1&n @version group by 1 and aname
vB1&s @version group by 1 and "1"
vB1&v @version group by 1 and @version
vB1,( @version group by 1 , (
vB1,f @version group by 1 , convert
vB1; @version group by 1 ;
vB1;c @version group by 1 ;  -- comment
vB1B( @version group by 1 group by (
vB1B1 @version group by 1 group by 1
vB1Bf @version group by 1 group by convert
vB1Bn @version group by 1 group by aname
vB1Bs @version group by 1 group by "1"
vB1Bv @version group by 1 group by @version
vB1U( @version group by 1 union (
vB1UE @version group by 1 union select
vB1c @version group by 1  -- comment
vB1k( @version group by 1 JOIN (
vB1k1 @version group by 1 JOIN 1
vB1kf @version group by 1 JOIN convert
vB1kn @version group by 1 JOIN aname
vB1ks @version group by 1 JOIN "1"
vB1kv @version group by 1 JOIN @version
vB1o( @version group by 1 * (
vB1of @version group by 1 * convert
vB1os @version group by 1 * "1"
vB1ov @version group by 1 * @version
vBE(1 @version group by select ( 1
vBE(f @version group by select ( convert
vBE(n @version group by select ( aname
vBE(s @version group by select ( "1"
vBE(v @version group by select ( @version
vBEk( @version group by select JOIN (
vBf() @version group by convert ( )
vBf(1 @version group by convert ( 1
vBf(f @version group by convert ( convert
vBf(n @version group by convert ( aname
vBf(s @version group by convert ( "1"
vBf(v @version group by convert ( @version
vBn @version group by aname
vBn&( @version group by aname and (
vBn&1 @version group by aname and 1
vBn&f @version group by aname and convert
vBn&n @version group by aname and aname
vBn&s @version group by aname and "1"
vBn&v @version group by aname and @version
vBn,( @version group by aname , (
vBn,f @version group by aname , convert
vBn; @version group by aname ;
vBn;c @version group by aname ;  -- comment
vBnB( @version group by aname group by (
vBnB1 @version group by aname group by 1
vBnBf @version group by aname group by convert
vBnBn @version group by aname group by aname
vBnBs @version group by aname group by "1"
vBnBv @version group by aname group by @version
vBnU( @version group by aname union (
vBnUE @version group by aname union select
vBnc @version group by aname  -- comment
vBnk( @version group by aname JOIN (
vBnk1 @version group by aname JOIN 1
vBnkf @version group by aname JOIN convert
vBnkn @version group by aname JOIN aname
vBnks @version group by aname JOIN "1"
vBnkv @version group by aname JOIN @version
vBno( @version group by aname * (
vBnof @version group by aname * convert
vBnos @version group by aname * "1"
vBnov @version group by aname * @version
vBs @version group by "1"
vBs&( @version group by "1" and (
vBs&1 @version group by "1" and 1
vBs&f @version group by "1" and convert
vBs&n @version group by "1" and aname
vBs&s @version group by "1" and "1"
vBs&v @version group by "1" and @version
vBs,( @version group by "1" , (
vBs,f @version group by "1" , convert
vBs; @version group by "1" ;
vBs;c @version group by "1" ;  -- comment
vBsB( @version group by "1" group by (
vBsB1 @version group by "1" group by 1
vBsBf @version group by "1" group by convert
vBsBn @version group by "1" group by aname
vBsBs @version group by "1" group by "1"
vBsBv @version group by "1" group by @version
vBsU( @version group by "1" union (
vBsUE @version group by "1" union select
vBsc @version group by "1"  -- comment
vBsk( @version group by "1" JOIN (
vBsk1 @version group by "1" JOIN 1
vBskf @version group by "1" JOIN convert
vBskn @version group by "1" JOIN aname
vBsks @version group by "1" JOIN "1"
vBskv @version group by "1" JOIN @version
vBso( @version group by "1" * (
vBso1 @version group by "1" * 1
vBsof @version group by "1" * convert
vBson @version group by "1" * aname
vBsos @version group by "1" * "1"
vBsov @version group by "1" * @version
vBv @version group by @version
vBv&( @version group by @version and (
vBv&1 @version group by @version and 1
vBv&f @version group by @version and convert
vBv&n @version group by @version and aname
vBv&s @version group by @version and "1"
vBv&v @version group by @version and @version
vBv,( @version group by @version , (
vBv,f @version group by @version , convert
vBv; @version group by @version ;
vBv;c @version group by @version ;  -- comment
vBvB( @version group by @version group by (
vBvB1 @version group by @version group by 1
vBvBf @version group by @version group by convert
vBvBn @version group by @version group by aname
vBvBs @version group by @version group by "1"
vBvBv @version group by @version group by @version
vBvU( @version group by @version union (
vBvUE @version group by @version union select
vBvc @version group by @version  -- comment
vBvk( @version group by @version JOIN (
vBvk1 @version group by @version JOIN 1
vBvkf @version group by @version JOIN convert
vBvkn @version group by @version JOIN aname
vBvks @version group by @version JOIN "1"
vBvkv @version group by @version JOIN @version
vBvo( @version group by @version * (
vBvof @version group by @version * convert
vBvos @version group by @version * "1"
vE(1) @version select ( 1 )
vE(1o @version select ( 1 *
vE(f( @version select ( convert (
vE(n) @version select ( aname )
vE(no @version select ( aname *
vE(s) @version select ( "1" )
vE(so @version select ( "1" *
vE(v) @version select ( @version )
vE(vo @version select ( @version *
vE1;T @version select 1 ; DROP
vE1T( @version select 1 DROP (
vE1T1 @version select 1 DROP 1
vE1Tf @version select 1 DROP convert
vE1Tn @version select 1 DROP aname
vE1Ts @version select 1 DROP "1"
vE1Tv @version select 1 DROP @version
vE1UE @version select 1 union select
vE1c @version select 1  -- comment
vE1o( @version select 1 * (
vE1of @version select 1 * convert
vE1os @version select 1 * "1"
vE1ov @version select 1 * @version
vEU(1 @version select union ( 1
vEU(f @version select union ( convert
vEU(n @version select union ( aname
vEU(s @version select union ( "1"
vEU(v @version select union ( @version
vEU1, @version select union 1 ,
vEU1c @version select union 1  -- comment
vEU1o @version select union 1 *
vEUEf @version select union select convert
vEUEk @version select union select JOIN
vEUf( @version select union convert (
vEUs, @version select union "1" ,
vEUsc @version select union "1"  -- comment
vEUso @version select union "1" *
vEUv, @version select union @version ,
vEUvc @version select union @version  -- comment
vEUvo @version select union @version *
vEf() @version select convert ( )
vEf(1 @version select convert ( 1
vEf(f @version select convert ( convert
vEf(n @version select convert ( aname
vEf(s @version select convert ( "1"
vEf(v @version select convert ( @version
vEk(1 @version select JOIN ( 1
vEk(E @version select JOIN ( select
vEk(f @version select JOIN ( convert
vEk(n @version select JOIN ( aname
vEk(s @version select JOIN ( "1"
vEk(v @version select JOIN ( @version
vEk1; @version select JOIN 1 ;
vEk1T @version select JOIN 1 DROP
vEk1U @version select JOIN 1 union
vEk1c @version select JOIN 1  -- comment
vEk1o @version select JOIN 1 *
vEkU( @version select JOIN union (
vEkU1 @version select JOIN union 1
vEkUE @version select JOIN union select
vEkUf @version select JOIN union convert
vEkUs @version select JOIN union "1"
vEkUv @version select JOIN union @version
vEkf( @version select JOIN convert (
vEkn; @version select JOIN aname ;
vEknE @version select JOIN aname select
vEknT @version select JOIN aname DROP
vEknU @version select JOIN aname union
vEknc @version select JOIN aname  -- comment
vEkok @version select JOIN * JOIN
vEks; @version select JOIN "1" ;
vEksT @version select JOIN "1" DROP
vEksU @version select JOIN "1" union
vEksc @version select JOIN "1"  -- comment
vEkso @version select JOIN "1" *
vEkv; @version select JOIN @version ;
vEkvT @version select JOIN @version DROP
vEkvU @version select JOIN @version union
vEkvc @version select JOIN @version  -- comment
vEkvo @version select JOIN @version *
vEn;T @version select aname ; DROP
vEnEn @version select aname select aname
vEnT( @version select aname DROP (
vEnT1 @version select aname DROP 1
vEnTf @version select aname DROP convert
vEnTn @version select aname DROP aname
vEnTs @version select aname DROP "1"
vEnTv @version select aname DROP @version
vEnUE @version select aname union select
vEnc @version select aname  -- comment
vEno( @version select aname * (
vEnof @version select aname * convert
vEnos @version select aname * "1"
vEnov @version select aname * @version
vEokn @version select * JOIN aname
vEs;T @version select "1" ; DROP
vEsT( @version select "1" DROP (
vEsT1 @version select "1" DROP 1
vEsTf @version select "1" DROP convert
vEsTn @version select "1" DROP aname
vEsTs @version select "1" DROP "1"
vEsTv @version select "1" DROP @version
vEsUE @version select "1" union select
vEsc @version select "1"  -- comment
vEso( @version select "1" * (
vEso1 @version select "1" * 1
vEsof @version select "1" * convert
vEson @version select "1" * aname
vEsos @version select "1" * "1"
vEsov @version select "1" * @version
vEv;T @version select @version ; DROP
vEvT( @version select @version DROP (
vEvT1 @version select @version DROP 1
vEvTf @version select @version DROP convert
vEvTn @version select @version DROP aname
vEvTs @version select @version DROP "1"
vEvTv @version select @version DROP @version
vEvUE @version select @version union select
vEvc @version select @version  -- comment
vEvo( @version select @version * (
vEvof @version select @version * convert
vEvos @version select @version * "1"
vT(1) @version DROP ( 1 )
vT(1o @version DROP ( 1 *
vT(f( @version DROP ( convert (
vT(n) @version DROP ( aname )
vT(no @version DROP ( aname *
vT(s) @version DROP ( "1" )
vT(so @version DROP ( "1" *
vT(v) @version DROP ( @version )
vT(vo @version DROP ( @version *
vT1(f @version DROP 1 ( convert
vT1o( @version DROP 1 * (
vT1of @version DROP 1 * convert
vT1os @version DROP 1 * "1"
vT1ov @version DROP 1 * @version
vTE(1 @version DROP select ( 1
vTE(f @version DROP select ( convert
vTE(n @version DROP select ( aname
vTE(s @version DROP select ( "1"
vTE(v @version DROP select ( @version
vTE1n @version DROP select 1 aname
vTE1o @version DROP select 1 *
vTEf( @version DROP select convert (
vTEk( @version DROP select JOIN (
vTEk1 @version DROP select JOIN 1
vTEkf @version DROP select JOIN convert
vTEkn @version DROP select JOIN aname
vTEks @version DROP select JOIN "1"
vTEkv @version DROP select JOIN @version
vTEnn @version DROP select aname aname
vTEno @version DROP select aname *
vTEsn @version DROP select "1" aname
vTEso @version DROP select "1" *
vTEvn @version DROP select @version aname
vTEvo @version DROP select @version *
vTTnE @version DROP DROP aname select
vTTnT @version DROP DROP aname DROP
vTTnk @version DROP DROP aname JOIN
vTTnn @version DROP DROP aname aname
vTf() @version DROP convert ( )
vTf(1 @version DROP convert ( 1
vTf(f @version DROP convert ( convert
vTf(n @version DROP convert ( aname
vTf(s @version DROP convert ( "1"
vTf(v @version DROP convert ( @version
vTn(1 @version DROP aname ( 1
vTn(f @version DROP aname ( convert
vTn(s @version DROP aname ( "1"
vTn(v @version DROP aname ( @version
vTn1c @version DROP aname 1  -- comment
vTn1o @version DROP aname 1 *
vTn;E @version DROP aname ; select
vTn;T @version DROP aname ; DROP
vTn;n @version DROP aname ; aname
vTnE( @version DROP aname select (
vTnE1 @version DROP aname select 1
vTnEf @version DROP aname select convert
vTnEn @version DROP aname select aname
vTnEs @version DROP aname select "1"
vTnEv @version DROP aname select @version
vTnT( @version DROP aname DROP (
vTnT1 @version DROP aname DROP 1
vTnTf @version DROP aname DROP convert
vTnTn @version DROP aname DROP aname
vTnTs @version DROP aname DROP "1"
vTnTv @version DROP aname DROP @version
vTnf( @version DROP aname convert (
vTnkn @version DROP aname JOIN aname
vTnn: @version DROP aname aname :
vTnnc @version DROP aname aname  -- comment
vTnno @version DROP aname aname *
vTno( @version DROP aname * (
vTnof @version DROP aname * convert
vTnos @version DROP aname * "1"
vTnov @version DROP aname * @version
vTnsc @version DROP aname "1"  -- comment
vTnso @version DROP aname "1" *
vTnvc @version DROP aname @version  -- comment
vTnvo @version DROP aname @version *
vTs(f @version DROP "1" ( convert
vTso( @version DROP "1" * (
vTso1 @version DROP "1" * 1
vTsof @version DROP "1" * convert
vTson @version DROP "1" * aname
vTsos @version DROP "1" * "1"
vTsov @version DROP "1" * @version
vTv(1 @version DROP @version ( 1
vTv(f @version DROP @version ( convert
vTvo( @version DROP @version * (
vTvof @version DROP @version * convert
vTvos @version DROP @version * "1"
vU @version union
vU(1) @version union ( 1 )
vU(1o @version union ( 1 *
vU(E( @version union ( select (
vU(E1 @version union ( select 1
vU(Ef @version union ( select convert
vU(Ek @version union ( select JOIN
vU(En @version union ( select aname
vU(Es @version union ( select "1"
vU(Ev @version union ( select @version
vU(f( @version union ( convert (
vU(n) @version union ( aname )
vU(no @version union ( aname *
vU(s) @version union ( "1" )
vU(so @version union ( "1" *
vU(v) @version union ( @version )
vU(vo @version union ( @version *
vU1,( @version union 1 , (
vU1,f @version union 1 , convert
vU1c @version union 1  -- comment
vU1o( @version union 1 * (
vU1of @version union 1 * convert
vU1os @version union 1 * "1"
vU1ov @version union 1 * @version
vU; @version union ;
vU;c @version union ;  -- comment
vUE @version union select
vUE(1 @version union select ( 1
vUE(E @version union select ( select
vUE(f @version union select ( convert
vUE(n @version union select ( aname
vUE(o @version union select ( *
vUE(s @version union select ( "1"
vUE(v @version union select ( @version
vUE1 @version union select 1
vUE1& @version union select 1 and
vUE1( @version union select 1 (
vUE1) @version union select 1 )
vUE1, @version union select 1 ,
vUE1; @version union select 1 ;
vUE1B @version union select 1 group by
vUE1U @version union select 1 union
vUE1c @version union select 1  -- comment
vUE1f @version union select 1 convert
vUE1k @version union select 1 JOIN
vUE1n @version union select 1 aname
vUE1o @version union select 1 *
vUE1s @version union select 1 "1"
vUE1v @version union select 1 @version
vUE; @version union select ;
vUE;c @version union select ;  -- comment
vUEc @version union select  -- comment
vUEf @version union select convert
vUEf( @version union select convert (
vUEf, @version union select convert ,
vUEf; @version union select convert ;
vUEfc @version union select convert  -- comment
vUEk @version union select JOIN
vUEk( @version union select JOIN (
vUEk1 @version union select JOIN 1
vUEk; @version union select JOIN ;
vUEkc @version union select JOIN  -- comment
vUEkf @version union select JOIN convert
vUEkn @version union select JOIN aname
vUEko @version union select JOIN *
vUEks @version union select JOIN "1"
vUEkv @version union select JOIN @version
vUEn @version union select aname
vUEn& @version union select aname and
vUEn( @version union select aname (
vUEn) @version union select aname )
vUEn, @version union select aname ,
vUEn1 @version union select aname 1
vUEn; @version union select aname ;
vUEnB @version union select aname group by
vUEnU @version union select aname union
vUEnc @version union select aname  -- comment
vUEnf @version union select aname convert
vUEnk @version union select aname JOIN
vUEno @version union select aname *
vUEns @version union select aname "1"
vUEok @version union select * JOIN
vUEon @version union select * aname
vUEs @version union select "1"
vUEs& @version union select "1" and
vUEs( @version union select "1" (
vUEs) @version union select "1" )
vUEs, @version union select "1" ,
vUEs1 @version union select "1" 1
vUEs; @version union select "1" ;
vUEsB @version union select "1" group by
vUEsU @version union select "1" union
vUEsc @version union select "1"  -- comment
vUEsf @version union select "1" convert
vUEsk @version union select "1" JOIN
vUEso @version union select "1" *
vUEsv @version union select "1" @version
vUEv @version union select @version
vUEv& @version union select @version and
vUEv( @version union select @version (
vUEv) @version union select @version )
vUEv, @version union select @version ,
vUEv; @version union select @version ;
vUEvB @version union select @version group by
vUEvU @version union select @version union
vUEvc @version union select @version  -- comment
vUEvf @version union select @version convert
vUEvk @version union select @version JOIN
vUEvn @version union select @version aname
vUEvo @version union select @version *
vUEvs @version union select @version "1"
vUTn( @version union DROP aname (
vUTn1 @version union DROP aname 1
vUTnf @version union DROP aname convert
vUTnn @version union DROP aname aname
vUTns @version union DROP aname "1"
vUTnv @version union DROP aname @version
vUc @version union  -- comment
vUf() @version union convert ( )
vUf(1 @version union convert ( 1
vUf(f @version union convert ( convert
vUf(n @version union convert ( aname
vUf(s @version union convert ( "1"
vUf(v @version union convert ( @version
vUk(E @version union JOIN ( select
vUo(E @version union * ( select
vUon( @version union * aname (
vUon1 @version union * aname 1
vUonf @version union * aname convert
vUons @version union * aname "1"
vUs,( @version union "1" , (
vUs,f @version union "1" , convert
vUsc @version union "1"  -- comment
vUso( @version union "1" * (
vUso1 @version union "1" * 1
vUsof @version union "1" * convert
vUson @version union "1" * aname
vUsos @version union "1" * "1"
vUsov @version union "1" * @version
vUv,( @version union @version , (
vUv,f @version union @version , convert
vUvc @version union @version  -- comment
vUvo( @version union @version * (
vUvof @version union @version * convert
vUvos @version union @version * "1"
vc @version  -- comment
vf()1 @version convert ( ) 1
vf()U @version convert ( ) union
vf()f @version convert ( ) convert
vf()k @version convert ( ) JOIN
vf()n @version convert ( ) aname
vf()o @version convert ( ) *
vf()s @version convert ( ) "1"
vf()v @version convert ( ) @version
vf(1) @version convert ( 1 )
vf(1n @version convert ( 1 aname
vf(1o @version convert ( 1 *
vf(E( @version convert ( select (
vf(E1 @version convert ( select 1
vf(Ef @version convert ( select convert
vf(Ek @version convert ( select JOIN
vf(En @version convert ( select aname
vf(Es @version convert ( select "1"
vf(Ev @version convert ( select @version
vf(f( @version convert ( convert (
vf(n) @version convert ( aname )
vf(n, @version convert ( aname ,
vf(no @version convert ( aname *
vf(s) @version convert ( "1" )
vf(so @version convert ( "1" *
vf(v) @version convert ( @version )
vf(vo @version convert ( @version *
vk(1) @version JOIN ( 1 )
vk(1o @version JOIN ( 1 *
vk(f( @version JOIN ( convert (
vk(n) @version JOIN ( aname )
vk(no @version JOIN ( aname *
vk(s) @version JOIN ( "1" )
vk(so @version JOIN ( "1" *
vk(v) @version JOIN ( @version )
vk(vo @version JOIN ( @version *
vk)&( @version JOIN ) and (
vk)&1 @version JOIN ) and 1
vk)&f @version JOIN ) and convert
vk)&n @version JOIN ) and aname
vk)&s @version JOIN ) and "1"
vk)&v @version JOIN ) and @version
vk);E @version JOIN ) ; select
vk);T @version JOIN ) ; DROP
vk)B( @version JOIN ) group by (
vk)B1 @version JOIN ) group by 1
vk)Bf @version JOIN ) group by convert
vk)Bn @version JOIN ) group by aname
vk)Bs @version JOIN ) group by "1"
vk)Bv @version JOIN ) group by @version
vk)E( @version JOIN ) select (
vk)E1 @version JOIN ) select 1
vk)Ef @version JOIN ) select convert
vk)Ek @version JOIN ) select JOIN
vk)En @version JOIN ) select aname
vk)Es @version JOIN ) select "1"
vk)Ev @version JOIN ) select @version
vk)UE @version JOIN ) union select
vk)f( @version JOIN ) convert (
vk)o( @version JOIN ) * (
vk)of @version JOIN ) * convert
vk1 @version JOIN 1
vk1&( @version JOIN 1 and (
vk1&1 @version JOIN 1 and 1
vk1&f @version JOIN 1 and convert
vk1&n @version JOIN 1 and aname
vk1&s @version JOIN 1 and "1"
vk1&v @version JOIN 1 and @version
vk1; @version JOIN 1 ;
vk1;E @version JOIN 1 ; select
vk1;T @version JOIN 1 ; DROP
vk1;c @version JOIN 1 ;  -- comment
vk1B( @version JOIN 1 group by (
vk1B1 @version JOIN 1 group by 1
vk1Bf @version JOIN 1 group by convert
vk1Bn @version JOIN 1 group by aname
vk1Bs @version JOIN 1 group by "1"
vk1Bv @version JOIN 1 group by @version
vk1E( @version JOIN 1 select (
vk1E1 @version JOIN 1 select 1
vk1Ef @version JOIN 1 select convert
vk1Ek @version JOIN 1 select JOIN
vk1En @version JOIN 1 select aname
vk1Es @version JOIN 1 select "1"
vk1Ev @version JOIN 1 select @version
vk1U( @version JOIN 1 union (
vk1UE @version JOIN 1 union select
vk1c @version JOIN 1  -- comment
vk1o( @version JOIN 1 * (
vk1of @version JOIN 1 * convert
vk1os @version JOIN 1 * "1"
vk1ov @version JOIN 1 * @version
vkUE( @version JOIN union select (
vkUE1 @version JOIN union select 1
vkUEf @version JOIN union select convert
vkUEk @version JOIN union select JOIN
vkUEn @version JOIN union select aname
vkUEs @version JOIN union select "1"
vkUEv @version JOIN union select @version
vkf() @version JOIN convert ( )
vkf(1 @version JOIN convert ( 1
vkf(f @version JOIN convert ( convert
vkf(n @version JOIN convert ( aname
vkf(s @version JOIN convert ( "1"
vkf(v @version JOIN convert ( @version
vkn @version JOIN aname
vkn&( @version JOIN aname and (
vkn&1 @version JOIN aname and 1
vkn&f @version JOIN aname and convert
vkn&n @version JOIN aname and aname
vkn&s @version JOIN aname and "1"
vkn&v @version JOIN aname and @version
vkn; @version JOIN aname ;
vkn;E @version JOIN aname ; select
vkn;T @version JOIN aname ; DROP
vkn;c @version JOIN aname ;  -- comment
vknB( @version JOIN aname group by (
vknB1 @version JOIN aname group by 1
vknBf @version JOIN aname group by convert
vknBn @version JOIN aname group by aname
vknBs @version JOIN aname group by "1"
vknBv @version JOIN aname group by @version
vknE( @version JOIN aname select (
vknE1 @version JOIN aname select 1
vknEf @version JOIN aname select convert
vknEn @version JOIN aname select aname
vknEs @version JOIN aname select "1"
vknEv @version JOIN aname select @version
vknU( @version JOIN aname union (
vknUE @version JOIN aname union select
vknc @version JOIN aname  -- comment
vks @version JOIN "1"
vks&( @version JOIN "1" and (
vks&1 @version JOIN "1" and 1
vks&f @version JOIN "1" and convert
vks&n @version JOIN "1" and aname
vks&s @version JOIN "1" and "1"
vks&v @version JOIN "1" and @version
vks; @version JOIN "1" ;
vks;E @version JOIN "1" ; select
vks;T @version JOIN "1" ; DROP
vks;c @version JOIN "1" ;  -- comment
vksB( @version JOIN "1" group by (
vksB1 @version JOIN "1" group by 1
vksBf @version JOIN "1" group by convert
vksBn @version JOIN "1" group by aname
vksBs @version JOIN "1" group by "1"
vksBv @version JOIN "1" group by @version
vksE( @version JOIN "1" select (
vksE1 @version JOIN "1" select 1
vksEf @version JOIN "1" select convert
vksEk @version JOIN "1" select JOIN
vksEn @version JOIN "1" select aname
vksEs @version JOIN "1" select "1"
vksEv @version JOIN "1" select @version
vksU( @version JOIN "1" union (
vksUE @version JOIN "1" union select
vksc @version JOIN "1"  -- comment
vkso( @version JOIN "1" * (
vkso1 @version JOIN "1" * 1
vksof @version JOIN "1" * convert
vkson @version JOIN "1" * aname
vksos @version JOIN "1" * "1"
vksov @version JOIN "1" * @version
vkv @version JOIN @version
vkv&( @version JOIN @version and (
vkv&1 @version JOIN @version and 1
vkv&f @version JOIN @version and convert
vkv&n @version JOIN @version and aname
vkv&s @version JOIN @version and "1"
vkv&v @version JOIN @version and @version
vkv; @version JOIN @version ;
vkv;E @version JOIN @version ; select
vkv;T @version JOIN @version ; DROP
vkv;c @version JOIN @version ;  -- comment
vkvB( @version JOIN @version group by (
vkvB1 @version JOIN @version group by 1
vkvBf @version JOIN @version group by convert
vkvBn @version JOIN @version group by aname
vkvBs @version JOIN @version group by "1"
vkvBv @version JOIN @version group by @version
vkvE( @version JOIN @version select (
vkvE1 @version JOIN @version select 1
vkvEf @version JOIN @version select convert
vkvEk @version JOIN @version select JOIN
vkvEn @version JOIN @version select aname
vkvEs @version JOIN @version select "1"
vkvEv @version JOIN @version select @version
vkvU( @version JOIN @version union (
vkvUE @version JOIN @version union select
vkvc @version JOIN @version  -- comment
vkvo( @version JOIN @version * (
vkvof @version JOIN @version * convert
vkvos @version JOIN @version * "1"
vo(1& @version * ( 1 and
vo(1) @version * ( 1 )
vo(1, @version * ( 1 ,
vo(1o @version * ( 1 *
vo(E( @version * ( select (
vo(E1 @version * ( select 1
vo(EE @version * ( select select
vo(Ef @version * ( select convert
vo(Ek @version * ( select JOIN
vo(En @version * ( select aname
vo(Eo @version * ( select *
vo(Es @version * ( select "1"
vo(Ev @version * ( select @version
vo(f( @version * ( convert (
vo(n& @version * ( aname and
vo(n) @version * ( aname )
vo(n, @version * ( aname ,
vo(no @version * ( aname *
vo(s& @version * ( "1" and
vo(s) @version * ( "1" )
vo(s, @version * ( "1" ,
vo(so @version * ( "1" *
vo(v& @version * ( @version and
vo(v) @version * ( @version )
vo(v, @version * ( @version ,
vo(vo @version * ( @version *
voU(E @version * union ( select
voUEk @version * union select JOIN
voUEn @version * union select aname
vof() @version * convert ( )
vof(1 @version * convert ( 1
vof(E @version * convert ( select
vof(f @version * convert ( convert
vof(n @version * convert ( aname
vof(s @version * convert ( "1"
vof(v @version * convert ( @version
vok&( @version * JOIN and (
vok&1 @version * JOIN and 1
vok&f @version * JOIN and convert
vok&n @version * JOIN and aname
vok&s @version * JOIN and "1"
vok&v @version * JOIN and @version
vok(1 @version * JOIN ( 1
vok(f @version * JOIN ( convert
vok(n @version * JOIN ( aname
vok(s @version * JOIN ( "1"
vok(v @version * JOIN ( @version
vok1c @version * JOIN 1  -- comment
vok1o @version * JOIN 1 *
vokf( @version * JOIN convert (
voknc @version * JOIN aname  -- comment
voko( @version * JOIN * (
voko1 @version * JOIN * 1
vokof @version * JOIN * convert
vokon @version * JOIN * aname
vokos @version * JOIN * "1"
vokov @version * JOIN * @version
voksc @version * JOIN "1"  -- comment
vokso @version * JOIN "1" *
vokvc @version * JOIN @version  -- comment
vokvo @version * JOIN @version *
vos @version * "1"
vos&( @version * "1" and (
vos&1 @version * "1" and 1
vos&E @version * "1" and select
vos&U @version * "1" and union
vos&f @version * "1" and convert
vos&k @version * "1" and JOIN
vos&n @version * "1" and aname
vos&s @version * "1" and "1"
vos&v @version * "1" and @version
vos(E @version * "1" ( select
vos(U @version * "1" ( union
vos)& @version * "1" ) and
vos), @version * "1" ) ,
vos); @version * "1" ) ;
vos)B @version * "1" ) group by
vos)E @version * "1" ) select
vos)U @version * "1" ) union
vos)c @version * "1" )  -- comment
vos)f @version * "1" ) convert
vos)k @version * "1" ) JOIN
vos)o @version * "1" ) *
vos,( @version * "1" , (
vos,f @version * "1" , convert
vos1( @version * "1" 1 (
vos1U @version * "1" 1 union
vos1f @version * "1" 1 convert
vos1n @version * "1" 1 aname
vos1s @version * "1" 1 "1"
vos1v @version * "1" 1 @version
vos; @version * "1" ;
vos;E @version * "1" ; select
vos;T @version * "1" ; DROP
vos;c @version * "1" ;  -- comment
vos;n @version * "1" ; aname
vosA( @version * "1" COLLATE (
vosAf @version * "1" COLLATE convert
vosAs @version * "1" COLLATE "1"
vosAt @version * "1" COLLATE binary
vosAv @version * "1" COLLATE @version
vosB( @version * "1" group by (
vosB1 @version * "1" group by 1
vosBE @version * "1" group by select
vosBf @version * "1" group by convert
vosBn @version * "1" group by aname
vosBs @version * "1" group by "1"
vosBv @version * "1" group by @version
vosE( @version * "1" select (
vosE1 @version * "1" select 1
vosEU @version * "1" select union
vosEf @version * "1" select convert
vosEk @version * "1" select JOIN
vosEn @version * "1" select aname
vosEo @version * "1" select *
vosEs @version * "1" select "1"
vosEv @version * "1" select @version
vosT( @version * "1" DROP (
vosT1 @version * "1" DROP 1
vosTE @version * "1" DROP select
vosTT @version * "1" DROP DROP
vosTf @version * "1" DROP convert
vosTn @version * "1" DROP aname
vosTs @version * "1" DROP "1"
vosTv @version * "1" DROP @version
vosU @version * "1" union
vosU( @version * "1" union (
vosU1 @version * "1" union 1
vosU; @version * "1" union ;
vosUE @version * "1" union select
vosUT @version * "1" union DROP
vosUc @version * "1" union  -- comment
vosUf @version * "1" union convert
vosUk @version * "1" union JOIN
vosUo @version * "1" union *
vosUs @version * "1" union "1"
vosUv @version * "1" union @version
vosc @version * "1"  -- comment
vosf( @version * "1" convert (
vosk( @version * "1" JOIN (
vosk) @version * "1" JOIN )
vosk1 @version * "1" JOIN 1
voskB @version * "1" JOIN group by
voskU @version * "1" JOIN union
voskf @version * "1" JOIN convert
voskn @version * "1" JOIN aname
vosks @version * "1" JOIN "1"
voskv @version * "1" JOIN @version
vosv( @version * "1" @version (
vosvU @version * "1" @version union
vosvf @version * "1" @version convert
vosvo @version * "1" @version *
vosvs @version * "1" @version "1"
```
