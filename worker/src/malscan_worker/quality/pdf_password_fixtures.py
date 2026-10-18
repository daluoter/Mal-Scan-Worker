"""Frozen, inert, real encrypted PDF inputs for password-resume acceptance.

Recipe v1 freezes pypdf 4.3.1 output so salts, file keys and IVs remain stable
without replacing a process-wide random generator. The public passwords below
are fixture data only. RC4 and revision-5 AES exist solely as legacy format tests.
The normal/action plaintext inputs are document_fixtures recipe v1; action PDFs
contain only ``void 0;`` and a nonexistent text filename, never executable payloads.
The ZIP uses pyzipper AES encryption and a different public fixture password.
"""

from __future__ import annotations

import base64
import hashlib
import zlib

PDF_PASSWORD = "quality-pdf-only"
PDF_OWNER_PASSWORD = "quality-pdf-owner-only"
ARCHIVE_PASSWORD = "quality-archive-only"
WRONG_PASSWORD = "quality-incorrect-only"

# profile: (expected SHA-256, expected bytes, compressed canonical fixture)
_FIXTURES: dict[str, tuple[str, int, str]] = {
    "rc4-40-normal": (
        "f34b5a619c19c50dc2f342be4a9194caaf7d3548e873e3f9cceae7cfc5a17134",
        879,
        "c-pN~O>Yx15WV|X_>v>|V?6d+igKWBBm}5cTDYJdy!JQ*MZ48zBencV4*Uc7BTP2XMhZu~T5I>sdv9i}@$BY"
        "u`O3ToG5h)J`wwBHmVNtG%;!SgJw1?A7imn}el65ZTGLKiCalC_A*d?{qCFE#JfSZ7eK$%Y)VodD$<GoFLV1"
        "58g?~y9i3VcnF_Zd0Ws~0Yk8Gj&vHJMl3$>zMzaKIe#SU!y;_ObGZ-&0?GYxXynn=1vTQO2<b1k(^zG~|;RA"
        "_i_vW+=n#Kr*>Pe@cUQnEUj(iC4#bKpsiPlrBN(hBvSy7l-)I?aitv(ZH#Y~;XlvmLnzbvvf6q@f6PE$0|ZY"
        "b^ShO68g&8D34L1SQ+hkW1DWiq6HNT_!>ZDeDleL62GIg-{>aB|$~+ZAi9hxol$tlGlMWU|X|^Aw~^VV~Zw3"
        "+h~V~fdXP{(GZ+=^*B%!T6&?Mm-L8$vdU-7aPL#3d%?Ur!;FP9%$joyPO))Fn=K8~vEFXJ5tpJ?eb1A09EZ1"
        "E?WOzkeaS;HXE}He2o0dO-hlDIi1ijCqi))n!_n!_J7#MLQw%&V{)YvR<5ic3r-xDE-y5<U(=bj4iZ+PZ?CN"
        "?cegotV+E)",
    ),
    "rc4-40-active-actions": (
        "bb36caa4458280a2b7114a2d6466890074dcb3d53628ac5416c01e510140471b",
        1145,
        "c-pO0%Wl*#6y5tPyy+5r{kElOq|$aIN>QsBV1ror*#=d~D3d`gKgohWfFI#zrc^<LSYbO-a&GRq4<GyF=6v~"
        "rzm(+U$Ioxy38z5&_?a{fVecL{g|f3ShWq}Ou$ypOwp8E`E5fcfr8`Yy+jmqQkkeB-IbBn||6VMnRk}Q}i6h"
        "oM8DVGrt{W*Q>`j}u^dps%Fa0!gm49`evKb1xKBe=v<TkwOACLlY3OGEU2wRnHzZ()}jtqY!rH+^n1rfHU>@"
        "s`_>ol~Rk+91(ZAz9(+9*M$<jtH$|BL1-?7DPE*pfDuD+jW=EF`GnmB1N`6h<56xOdenla%n;LIG1f#1e$^P"
        "D`FOKnisp)y$&a41M0EGSEgOtwcnZWO(G@p+>NRCs_oyPC?ej7vu}V`e=kNE@<Ut2|<I5s#ZRaVP`QuOq;Z#"
        "g0QR7-Hvxu0S2a+ukywUkA`J?KVlMWJ%%oaAx~Opw9k<X3>$LwCHTT|xLShDNmy4@5S(K-l+U12DO%c)z<R;"
        "8(FxLmu=li)R#|1LNm>gq0k{>m+G=za4x;gf7jWRB2cu(1MdhH4$Qf&n9Lt|q^)Qr5fI0%tgBq=+rj<Tp9Cv"
        "kZ>7FqT{1`KEgb96&Npb9}q(8#+92<ww-j`wD{&oAcV9IRO_jp_mnt$EZo|>okb5wpK9qQ8>E^!!xf)yw)Wi"
        "XO7XmJx_(16RK?65^<vTH=8w9+m92L+zFi!Ke1n~~bzH^Fuc!?<s})p*mKTwE{7FRg$Z@&",
    ),
    "aes-128-normal": (
        "cf6270701f72cb3a657c05049d1a740005e64c338032b37bdfaa2cd93a828dd8",
        1034,
        "c-pN~!EW0y487|sbjfkEBubP71Od7>0fwz;(QdsAJ;)Z-X6Wp~afWU`xx@Zo`;pO3*96Fpvte1J9-kgXYIb?"
        "HdZk~3nEm?w<EPM4$*%q^=5tYf`1VM$I!!}*=<Y;yneJ#K4Fj&kVj-x_BhVZLOgK@UcH4H4T2$}Wc_Tkb7z5"
        "?)K`8t)blj*X4&Cikol{<?H{BCcD1MFFeYc{zqD{B$8y3Y3OuJ{c2h5j!m$wb|a-Ncj9&`bN#<*PjVr&hGYz"
        "divP-3C1T@#F=hJveOVmQURwl3uaJ}6yND8WFm7^pyS8DrMbSgjf#9VP9J_5mS!EDphWP|n6;VoB;yp*v7`B"
        "P}O04)3YG8}6kxfptr3qK)WHG@@Fq9|q2$x*k%SQ=dh3A?J`GKqhOf*QvNvr_#ilJZox7Gz}6E80Rp%l2ZUr"
        "=skFo!4+Lhy%5z$Ik!-Js*OjF4LOa36c7t2l~uCEn@|@^jx2c>lGSLHVjD~0oU{tea=IEzz~b`r>|{IKFTaj"
        "etj@aT;*r`BbS|rt<@Jr(CyLK?<IpcFxg!{j{>9iI*;7wND2YP7JQAG)CyRXXX+GF#rQQ3`9{IF^BcIX7KJW"
        "*8L!Z_U)K4|LUVkT+QeAZ&H~Fqp-?pWb_IZBB{W=E?fZPRKCWi(!Xax3f|3PH0okqs+>SUp1G;cbs0lLNipx"
        "~RbY@7bu;~?GN%exs;KTHRT!HC&xd9f0I0I(wjF#",
    ),
    "aes-128-active-actions": (
        "e149d9fe9a04e6695a93f733ef055a775966332d7dc6e90ba361295ba0d6abef",
        1413,
        "c-pO0O>f*b5WVYH@Zw`DlEWF2z`}rQdx542Y<SyTf*klUw6}02L)HdK|6~vS2k9T_XzkcrY|&FC?Mi&)ym=f"
        "x^5ptr{hj$9x|6Se{qbjKlvZQ@wOg&a{^u_btorjbr~C1?>#x%-KPoE&Zo2;Jfrqm)Z^uEoC*<r*EkRcb_wC"
        "cu<>8?&Z1#wCPuBJ4<8GLh>H43x^-+CLu*9m52cht<p^KV{CG=U&JFeUG!}wV!wA@xd{XTa64L^>%sfco6_="
        "hNW#QZd&uHUHsP5P8JW!gT>UH@jIR@$}@xEN;Cj#AYo7>LHXh@8B&*|IiB)|6mfhL~$(2rh8sCd2SBG5%NLw"
        "`n(&yRKiW6~#mpT(ew!sSPU?NAikMl7<>IV|J-#3$3`=TFS*)=3uC1$6Uyi)-V<wn=RREU<Y80@tQ&^Xd}3i"
        "oG}zIBx$tRe5hGd%A64Wp=LVJd_9eIS9nsZoUvi377IyHOr`?hi48ilh_*hL+;a7$MANF%Oxidb9b_Mj_lO2"
        "^Nf48c79-h!I&0C>vL~WiOO*;YXrQ&LY;)DkL&KJVa>y|sD)a{m-zz68zx=)B;dZ`L#s<-?mfVrNjaCZ0y`N"
        "<c{bo)>O;cU0yMhV<Dm&}ENexp@t;EcpVl6G&LJSNRkt(*D0(d6x!P^ShOtT`W|3%DFe4_+ZVsOc`$rU7}FW"
        "|5>%3wooj*%UEsk}4fWPXg)WDT{^L0Hb$``xse>+{#yZoa$xv{=5s7|XK#mO<~tJC~dH_I0B4Y;p<xZLOXNm"
        "d5nbcrDrIiCd>t==95_2oX><^@16(>%M1r!HhP?80jO-;xPvPI97acgn0w6*gU1}Jx}|!-E4nnk=);mqnsR1"
        "+yBR*jf$SXFXRwd$udeRG9VWbIIv*FqYfgF^n?Wwi!FVDP;N_0KME=qhH(0SP{{FfIh5(k!>s(bL-BD=)4VU"
        "d(N=dSCzn_2?r*1OXu1",
    ),
    "aes-256-normal": (
        "28123ebbad2895e3e1e63a0ef150af7d2224530a0a0df0e5fd82247525082cf3",
        1282,
        "c-pO0&2A($5We?Q_>v>EUFBbC6lqCjBm}FB64(pcL%Cee4$96%oetXNB{}d0@FG-CLNZb~(yeZ}%3po1U!QF"
        "+H{ZB#aX9<y??3(=oU!Ime;rn<Vf^Xqy_oTWX1Y7v4&#<?<-vdgu7~sULH2C{!W)AlZWu2PkNerUVf<m&9?U"
        "NW7en*$#1#M2bUA1eHGMj1d@pTB-yOavh1D1A)Aw;0ujS$JII%jV3`+aT>`$1t)1f`GOlH+FQLci)dT`ZQVN"
        "V4~gc+!Ev$d3h&Ng2xxZYw@F{F|LK*)@lYigWpwvCfdNLgIAu?Mi26;Uxns_2zQEZLN7f|fXiP%T5PryhnA4"
        "?mco!I(IVKg#}g{$wENdTTrsUt)p+!?@Yq%^JgaGt<7&)Q0iOtSAD9;A(e-oNTr^ht%5QlFPv&NJAf5vJ!f#"
        "Uc_Njv~9!?ITHjT0EC`mjS>o`)*)527E09U&xi46vr3+vb)|UdvG+*bb1bof1Fq~lc0kus0hd|{g{2VJsy=v"
        "IYm6bV>y91e;+o^kv8FD*I%)-S)_pzYVzZP`gKN*LcaQU@^>0fTjF$(#x|jU|dT+*e>zfbwk|>1dx~u8ujd>"
        "zigy~hdTANi|$|eX|D_SG5OCdVVjw9PKii?~QfptDN!LBI>Zs3aNlr2_-B@s%~uu?4o$k;Qn7ca?S$*PDgP;"
        "1dA8$AX>^f`0!)Dt)a-=)~14KQwH`mFuhee5Mt5=F6qBudQ4s<O(!c-ksoCh3FK_OLIH(X?SO-Mr|WHq>!v|"
        "Ei1rjm`nS(W!%PbeK-~=81N9G97#MX7{@+oqByZ=x{$x==b}6F#dUcsdKtQhZrLU%sLVf9lD6Bfe5G*h5q<g"
        "jP4$#=oPJp9``VY^Z$cFZ;17tr?2<33IASN4>L{kF`)(RaCWx7+6?~y)$B&S",
    ),
    "aes-256-active-actions": (
        "a015d96b1cdb68b35bfeb1f93f24e2c0a6f407e9b3ab8d53377bc354024d717c",
        1661,
        "c-pO1&2Ahw48G4(=;C8Lk|<IVurT2I2WXnWhPTb7$U#4(y+yKXjK@LJm+YZ$kiJMcYu9nGMNiet0wYSKK9b+"
        "3J-Rx(_|AO~!_k+&{`hln#+qIIZCI^_@#oKXY{t_vm-oAyVZ16gd~dvNxE{vKJKmnOd9&M^@Mt+XF^kis!Tt"
        "RBczJo-muUVV>OR;op6(vDvvI@t)282>Ukxn2=G_Zd_*d5j&BW^Z1m_L+P5EK>NkdqDynXz=8^&wC-#tuCk!"
        "yr+K!t<Ij|mOq+KjKt$FgqI=58LwS8KC!E`mrU*PH9!hH6~~3k7rcTq2<$L4a0s5r?7J+Ij@;tx=6o^2>wqz"
        "Ycy~9=7dv7%$99VyleQa?6w;P~#9YN_16x6~%z!s*Ms#CR@>UWN3+kbEO1CUv&YwSI-Unf&v1wprVc96Lkd6"
        "O=9xF7n`tPb1{}y3A}jC;w5H!f%$6M^@qljSpjwhWdTV#1#Z!`*vac~>?2?;m0dt6A@uH?qDHLXd#~LV$yHH"
        "h3%z(o?3QY3TDnqNN!*caOpR*-z~CF&ESy@e97K;IO)kMpgz*K!w+6NIhKBJqZ*S&X<59n_Oz=5miavWS@aF"
        "xjIgIPMY<rpdLfsW>4pN&<p~os<t3)71$<1T!sYR-k2%=cm!D=#9wACqgh)&pfDY@I2VJWgp-7&|)TJEk@?%"
        "m4qF#cjzfov$zS!u4>Oj)VYJ(b{k3E)G8+8jp|8+&LWRKn7zOU|erwlzx-@yOcsAhu^4k+gA1Vz8y;>hzS;i"
        "@h4xbAS3ed6;j{KQ59P&vtE*@3QHQa_@Zo7M=?Q{z)Y2`r*Pn23RK3*U9C%S;fkhl}}MQ>Z1p)0Z>VwqU{`@"
        "aI`+hMxme-R>efN2uj+}R6#W^h0rjaEXUfZ+EOXkz#)lbUU(`>1rjG9N`29WkSA$e5Ca#T>Nd+7=8C5eD(>n"
        "WCQM7ql2u9e;#92_Yu@wl8v%ZrSO#m-V4sH}L_j0v+2&NH`<3mp%~^M7BYR-;cxY3C9M}*KZPCG3+dP%cd!F"
        "{3UT=P9g*;yGc6wtzUVA@oWoPK=`%Evt6=(%Oxd%FExsg103KSp%=}KBGqzn2cLVY|f>!?<M2<iC$2%*>R`L"
        "<1;?`9MK`7^km%QWu`?>wd9=;-|NV)z^ML$C7",
    ),
    "aes-256-r5-normal": (
        "dfd881186188b4c36dc271308c2bf17e2711deee6d1bac182356f1de601e7be5",
        1282,
        "c-pO0&2HQ_5We#%c=53j$>9u1U|}G&cY&e}Y}iRIK@R*GIvY4ELzauAFWE!ipnZ{!b{%^G=NJhR#E&!IeDgz"
        "{T%K=!v9Ca#{QKYE|0t`C9?NI7TB+gfw>#FuS)TLlc%z2Pe8czJiNTdRJypDGi=lhru(wmg+4!)VwN=CK+jg"
        "%%XjmNe$0Jwxq3aT8VsSl08s2c*=3mFJLSf`~=J0$}!xi6;4^tIU!XUKI%>Ib^avIx1<w>tnCJ0~(_7nm#RV"
        "=P$;*QRj1&D=HbRl;%&`s&i`xw}zikX~XEt`xOBS&XFH{t1pxtH1@_7>690G3lRo!LiXOb*Z)>pK+)e5??U6"
        "u#Fe$t<rwcy}{@(hf;<Ywwaz6kKv@*lcfS$ziyj^RDHoso_GedO+_Pt*xQONM7V7Y}M2jvtvs@B0ZE+y!ED9"
        "l5`W=27#(u#G+yE$VhfRKryLz=)oZQ49FPmsT$tt6$QX1M%_#L&1344eaNZ%UTe2KSU`%LQ*9NPxV2)VX{}L"
        "0l*pj~nc`}XsYeG^oUjsP>>`hhktk=IrG=7Qd;EI+Fn?PAxlF-uKGusn-YrIN^zeFp{T`kQ1@5u$;`(Ky4+P"
        "6%dR|<t^~(5+J_qovVDTQv8AfW-><A74qkygUP@Cjk%F;(uOO&oAs+9MI5E@J-La`{-PTAOOQ=k@%mF62CdZ"
        "2h{L5T#>aV|9_nJd$L4c7E7G?zSmk$Gh?G13#Z8KjEbtck6M=BoFu+I~DLUnlO$Xj10s(uAT~cm0G}8L0iv?"
        "inNh0<#WYV9vh8ARO_{Q{LY4w4c@M?O!ZXhO2Ru!+kiRzwP>{{p0t!oYNIp03tw$G8&F7$Sext$Uzd+@84o0"
        "yZaS+v6i6wJs>>&85Ht|Snule?QYii{ik(5=V{&-G=WhkC+mxi`XB7EMt1",
    ),
    "aes-256-r5-active-actions": (
        "6a1e8f7a680cd8e06af6aa5db00c071cb355f75ec1717ce4b86188ac44151d53",
        1661,
        "c-pO1&2Ahw48G4(=;C8L5-Cv<urT1pHqbPI4R4!Ekpm@B@fOamF&+m=U$Te3LHi=*tX*e|EqdzA>|jLk=i^6"
        "Gdvbk#`HlM)hm$}4{O$L_8EbasmtnOU#vi}jiy2?>%y+vF!+6af<iUU{+zjK@y=>3wyxDDyf0CS?nZ@YJg#G"
        "&Tba`ak7H@Fmb?<B#U+o^ZvvI@t!=^o$pA9ay=KX;w{;TPNW)d}hhVxe1hQHf=Ru@)puus4D!+0YPyT_?2a`"
        "o^JQ2xmCQ$oYIHsfpl#Ope3?&o2Ay*4WhEk#>v;sA|7f){DAWx-08eC*j$bkGunVmk+P9<%SYr-qJNISd^BE"
        "AShB+}7J+yfiD@V|1lyL`=3JxoD||0!ZkDLk=ONCe~&uKBF*}0<Lr`-C1chw;Um3N5Nu~Q<zCKft;hyRD0;H"
        "Iqz*Pfw-^>wKQ=(l^iMM;!{7wOb3{+r(JujGMSa?ac>ydqlC!dd{PE9M1fvX1m8+<*#=5V1$E3Jb0Qb0)KV;"
        "!M9`6J#oD{4-h8l?rBp_2MHIPpLQox32Gt2D(m}xb9x8d}Lxk}F;X4zw^2_UuY(LDm1_CK=;~{JA$_gmKo4Z"
        "+a7}qmz8&7R%-4&2@Zp_(vvdyBTMy*-Txy95#>)ML<6?DPc0M0>)zND5jLW|TQa@T5gQOr5_0KsW?wnL+(XX"
        "@!N{$y5?OVX+}ElWx$nliUig6$+J2hsw08@LC}5QCEFs+O)v51f@FvQgs{ZYlSwWEWHrmC5E}xrx%KQC?l{r"
        "*S>E=dZKJ`S#+|GBV@&t}f%dD81F*yI8-&7orfJheS<3UYaKd%VPSvxVkW_rJk+(Tmqz0lYnT_mR+}4Jl8;^"
        "c_<iYSfC_espvs^65MCG5TR~TOucyU-66-Ew4p;RwgQBVI#1|ye85EnvT3PGch0lpj*hFg0jQg6nLg@piz>A"
        "WH7fTtOI0x42c1JoQ~}|zRX$JB2W!$`UoJzc8%#GZGN)s@-`T#%oOQ=CvPUuq$1;q^wjmtLH0iIhdE(8TO#7"
        "Z*Z+;bpJl^bfdSX5ud*5&S&d~GsxgLHiOsJvAp<YDjQBx;RdKl@cVRcs}q#ODqEm0t#Wk0ACF=9IXKV0asd$"
        "Fz4m;2eozyAy#W}fCf@eU{rCnpzIm&0GU@~!;",
    ),
    "rc4-40-empty-user": (
        "868d93a35a0be29cec9d52ece35604aa8947587c038c452f45786061bc7bf957",
        879,
        "c-pN~%We}v5WLS<%*998ndx~-D<4Q=2?0vv1TH9tdGr_~Yd2c2rG%g4z#qVm&|X8bk~y;PsqU)k9`!D6E?2M"
        "QYha6?zrO!qk_+CaudHoZbNBRsyt#;D-1QsQ+{6v;xuS$MTP_)P<(R0>2vZ(wF8V_^a><%^+p_1MIUI@neny"
        "3VQjbOh67}TNe894eZ~8})5OgYWy6;)D#(jSnG8IJ%B>SSQXUaE2Uk(`u-n#5{!c=31ptK03M4ybuSc4VX+3"
        "c`7=ZdwMYpOPCZv%ScOR^b|-g6H#^Z0b^bIlcN-eb2Jzi=(cm}?buuucUEthT$6ifC@f*p)aG)?D*e2q~dho"
        "k~GlvZ=-y5Z(Z2uVbw`Ct-xkg|6yVmEKw9icAy(?QqGOkGze+DTm7F;L(ICz&o9^gy>8lMg%A*stJh7%cL>I"
        "1hFJ)D;qS~&AWOWurk3d6VC^?#(?3KKVy=5pCa80X7w2+6`Wy8o?|e_#vyKZI857myZwe#O0({JnxxY>yzOe"
        "w^`Gxc8j6<aU@aK%V63tdqy<8hRS*c()01*2I<2gxYyobHfi=tjAwlDK)#c&oVdUoTAF?0gFisn4lw*s<)%A"
        "+~23p(P0{",
    ),
    "aes-256-empty-user": (
        "85f04ec529dd34a0abbf631cd6156fff41394d860fddda99f4b377a01ddd1a4c",
        1282,
        "c-pO0&2Hp248Hp*bjh)`M2eII3<7ME8K7tv86@pqiaqFu%1)7;2^^=`?MwF1H)vm^^dwCNNRPE)L!!t}<i}4"
        "s+g@(Iao^%__SfHk{5d#d&7u4{tX9ML)7N`3<3*nH-Qji^xA|5c45-8PaDG0>zAcXMCgA8dj2DN;{cPMY{;+"
        "Eg<`;uYp!s+bivJn9Y&406KJ7HVm$u8_9lj`p)fep3_i-4n<>Bx+RZU6}6!sO_pCE6iLwl?;nN^0Asx1Xuk2"
        "MQ%tKv#;F=t0yk-S46dT$iE)XI=WQuirAY0)<5#bSe&E%+i0Qt3>=rJM@dj?q@JAXI}o#2UppVYY&pq{oCUo"
        "@PiV8GbON#TXvOA7y_#e=<Ni-Wm_dCk~Kc7&p7SS!)<?=DcrtYQuPCRt~#3@S%ybwK|GE*bt#wkHR5KZr%oV"
        "NY1%J>@DVsVjV|K63AE7LeN3T2%HnTM7`#2J>)J*#rZJ)Y*tCD6dRqhQU!=IR7sdBp+v`ll@al^HT`*;8G9#"
        "=F||~x^c*9j2alRwapD2NX%sP9>Zt|qNq4!}EG^XH+Vkk$<NRs;+oFQ;@=&ktWxqJRH{-kY%?ErT3gNl$8v1"
        "!-o&c7~^g6j(o0Zo#g;tiFSi9X)>Vd_U20<yI7&Aad4D8XC+`)MZ6qQzI8)wf85ekEaov+Xe<<^J=0&_&p)i"
        "3Py5=F&CB_yHVUF`^xC;~NAoY!_J%vPq)s@EV*iA%kA>jG77K4k4xvE3`Wv!_z|GD#n-%EP`qhKZ0&H!n7)f"
        ";z73Uv2E)*c{*+8@RVN3@3Q=ly`SB9kqJ1`&|~LULOv6xSvkw_xpY@{&{?<=X8Y*kr@di5`!wxF{%X^Fsaoa"
        "|LUWw#~FL|)=iIV$aMaHK<Evz-q-2t{cPypOY33I(|jZ}p&ic7)>oV1A0~T8p#",
    ),
    "zip-aes-pdf-aes-128": (
        "c2e63ba6ec4052340cdf7d0d9e315c9d3e04a645a6cde74021e76beb253d53bd",
        1595,
        "c-nnbYd8}M0Ns*>5-}D%R2m8umMPi{Yj>^Hykb|(W3<(<OtS8sl~*@X+4R_29yPB<WR0s4>Us|?B1IyxxswS"
        "=id#SK&wJ1L&N<)tzVrJKa2hMY03aX?Kuq)ubnWb}%+mw_QhsP1U^O5roDmyN-c5@RI~7jeMJGo9d8>YmQD_"
        "YSz!iF7H1BCMqM=SDV~vxCrOYMOUm0<ae4uFt>m{JBl)J?*fb-Ugw#6@w3MpA1=az;~LT@m9^Iw+?`@1U|Ac"
        "j=ZX+O`hC7)=l!h)!3vM-J~kaTW)gj0*s8b%<646k@-38w*+rAKG9ULI^Y=e7wQ(kyCD-EVwV9*{pm*-O?c7"
        "`WITGTgahWIGo$UA1O)o<;S-<fRGpP2+8ej{S&G)dM}J!UIjXFV98>%6*i*TXa)RnuLS0+ewySt39bcq@F3r"
        "&P8U<fHL9v?B9D!cKDaZQqDX~8;YJZI{H#{)~2WKw0CUZdN{a*Ho9T!gM~-LnOE5t_gD&3i2#4tH$0|}_@Lr"
        "x1<cD95Oh%8p<gpQcp_lnX*}e6X^xfWx&djzH0D!VLu50zEc~0iBY|r=mE3;Aw#Ku-PwxCUlzXu*B38JoqsA"
        "Au87U*_dUjdloN>FxHgYu~3RtaxY_l<@muJkwy?P>-Ok({66temNT>vrj7GfCf<fy>SPRY`FH|w%IN50S$#z"
        "7-42M&D41LXD|=(vIoZBDpz9%%MF$9^8Hi`wLulrxxwtbUd#?PeJZeo2#iITql`-?ndd-+d>&FlB$fg}stJ6"
        "@NCjqFa@gwK7(uUU(!LrAJdua<2^Xs{$y$5v(mSA%RlIpkvdY$JfSSrMU?R<l+FA=Zy_qC9yI3`)2Q4Y^TBc"
        "%nU=`XmEf5Mpu#s?E~`U??$PLGs%7%dn4b26KuYeT4^_c9_#8|m_TGsLDvRoh1k)LG>aHptoJMtz<t*nJ&gC"
        "=s@@2n%`7=cp)!5+7+d{JC7nSu&TUqF|8daVS8Wm#V#XZ`&aM<JGl;Pf{<j=p6A|fm@6VWB|KMTuJ|C-SsvA"
        "sMsMU^NQ>OQ|sT1tP#a`CzFTjWDG;;oEPk-O)dz23I>c4`yuU)QyFB!bj$E;{L)zMxtdj&OzU_!#$?q?@FI$"
        "~NE*{6Oy5qGQ-dyGkG<?nvMX7Oti$6(JH-Kk?@wK>aL8P-67!+0U%^Ut>Phi0*sO0T%~%0^bPLo#n8B4crib"
        "B%x1j<FCO^cGI*LK%7%zR_5n$C(WCq=St{f!XE}`R{h<;J0;--`jsR?laY{+xWvJ@+W8)%ZMOW6f~Hpvi+^n"
        "W7@<r>Fc!uWV66>?(6z4X`Q>V!<y=uVp_dc;GX4uhj*UHYp!_=Z((ND%Aovb!T^tx20Xv?GNPH|yN{008}Ma"
        "YBo>(>69=8#Ql+Zj^_i%JvYVVZj$5K3X}E8QS-}^t*M;hZP^1GI&*STur(6JM85V9m$;R8XoX{xWwzog>kF5"
        "MTQs$wy$?*x)yYja#cj1@LJDUm+E^W#p9nvqGOf^-dN#y0q#u*aRR6V%JwJ?{zl>wqe^DCJ^w#XwW6MqfW^H"
        "G+b`EBcyoeo7UZ$xz7pA$kqsU!Z0#0_+WaMekV5)<!G)|%Yg<yz<x?E6|jx!X`3h`l}EX+}ZmZ}V+G?9q1Hz"
        "Rx}p!4`j-X7bN&sJ9(4Mp&6Yn4c`ZS1hdPAoSncNk6wP&b5zmf-TOC+DG<xrib2Y8J29mFjT7?&;K<8-vjwt"
        "vN6NPz$KV=kTWvobVv)b_)4;HN?BbS5~O)Y1=ps@KkE+T{#;d*X427kIvLGLf%`Odjp#tXcS)B*(>>HdeLF%"
        "GAKiVwD0*{Eejmiqyd^PVeaFRS?4Fz62nRR!xnf4BY=|kUS4hx{$T8=`r#1{9u5!5#Lt!xRngKKJ@h4-T4Cq"
        "Q=0;MN7@fa2KhW*^%KRg;ZK24npE{eKyB@)jnN>eSYGN{Tv(z)HOe@*3%zesIVK?V9DF-=M`FMV-cJWExjy0"
        ")ryJ1!UGoGH`SDnd3}d)bNQ9t0e41z6+1&;4JV2mbW`yLtjn6ZCTf{J}#%@{Q)t_77p#^yd",
    ),
    "aes-128-orphan-stream": (
        'd379087938e51cca1b8337ecf298f45a71249ec957ce7cbbcc207a56cb9002be',
        1108,
        'c$}?MJ8Kj{9FOfZf;N@|dZaQt@7aarAdfo{jR|)qjYOE8$K@p14SRbbvB(#&5kW+(MO0Ay0D_ek79t`RcCiu'
        '>Ewm6DXD(;%@KU<V?9Tu7`#*j&wdIB8Sv*5QZU57ocK|~Ki|iUmQxIL=-Lf!RRvp^|(R|U*D~LgKp=)~Z3S{'
        '1~1=m2m4s32h2pJ1qE(_DwwuC96iI9e1ZAFZ^a8xM8GLbpuXch~uG1A&<q`1S}Qb`gW^Vo8pFsmiv^|1_eqP'
        'Tfgsg0ro4yuHq`qo$gJF*)PwQR5Gm)b{oi+7I}t?8<{V#hazX3$^}bg<R}cxglP|Df|R^ous{RO?W%VDD9>R'
        'h!`ZtMu8&<LT?G&7ZgL-#PK*)V-T8zdqiZdHekIqci3H@2MM?w%1Qif4KE+@5{pn$KJ0zoxVFK*^d{!UsK|9'
        '=Um7$gc@cPV;NT=^NobhFgGT#FBLM9Fh6pV5D+!H8<i&^YF8>Zsx%;4f+;mLrp7YDBvy{AOgWuoR*J-Emk=#'
        '1wUlr!40lGwR9YdWC&o}ukt3NO*9uIr5n2j@6DfTZRZJSH4apKBh)a@$#F=B3TV^GX6~lrd<YnQUQwXEjqs%'
        'wM_<eC^xSQ=)>y7O&>S&?ROItP%PKz*_ZM0X(s8JDy9B6A-n@xBC5QOqj7?HG7S_cr603AM1a85aN@KA?6l>'
        '<vY(n&U<!;(zs2*DFNdIX-QWu&W0)!ne=fX8<Cy7lEnt)i$P9UQUfeC`TJhWiD7C{rOQrIHH4Jb9QB>SaNM5'
        'ZM2j2x73u-Vagk^(<HiHvdvo{~r+kDl~Fk?rv33{JjgkN|n`M$Q~NhYK^5P_yZB+C;k'
    ),
}

PDF_PASSWORD_PROFILES = tuple(_FIXTURES)


def build_pdf_password_fixture(profile: str, recipe_version: int = 1) -> bytes:
    """Return checksum-verified canonical test bytes; reject unknown recipes."""
    if recipe_version != 1:
        raise ValueError("Unsupported PDF password fixture recipe version")
    if profile not in _FIXTURES:
        raise ValueError("Unknown PDF password fixture profile")
    expected_sha256, expected_size, compressed = _FIXTURES[profile]
    payload = zlib.decompress(base64.b85decode(compressed))
    if len(payload) != expected_size or hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError("PDF password fixture checksum differs")
    return payload
