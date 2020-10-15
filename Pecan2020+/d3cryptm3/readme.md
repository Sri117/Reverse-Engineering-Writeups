# Reverse Engineering (Advanced)

![d3cryptm3](https://user-images.githubusercontent.com/45506405/96070623-26fdfd00-0ed3-11eb-95a0-4ee92f95b825.png)

## Basic Static Analysis (BSA) - Step 1
**Downloading the file and running the "file" command shows that it is a linux executable:**

![d3cryptm3](https://user-images.githubusercontent.com/45506405/96070863-95db5600-0ed3-11eb-8acc-59be1579d408.png)

We can also see that the executable has been stripped

## BSA - Step 2 ##
**Executing the binary gives us the following output**

![d3cryptm3](https://user-images.githubusercontent.com/45506405/96071285-5e20de00-0ed4-11eb-8f7e-aa8840235933.png)

Looks like our input is being compared to something...

## BSA - Step 3 ##
**Open the binary using a disassembler/debugger**
```
sdevalpa@LAPTOP-LAFUS4CN:~$ r2 -w d3cryptm3
[0x000010b0]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Emulate code to find computed references (aae)
[x] Analyze consecutive function (aat)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[0x000010b0]> afl
0x00001000    3 23           sub.__gmon_start___232_0
0x00001030    1 6            sym.imp.puts
0x00001040    1 6            sym.imp.strlen
0x00001050    1 6            sym.imp.printf
0x00001060    1 6            sym.imp.fgets
0x00001070    1 6            sym.imp.strcmp
0x00001080    1 6            sym.imp.exit
0x00001090    1 6            sym.imp.sleep
0x000010a0    1 6            sub.__cxa_finalize_248_a0
0x000010b0    1 43           entry0
0x000010e0    3 33           sub._ITM_deregisterTMCloneTable_216_e0
0x00001150    4 49           entry2.fini
0x00001190    5 5    -> 56   entry1.init
0x00001195    1 261          main
0x0000129a    6 270          sub.Checking_each_byte..._29a
0x000013a8    3 75           sub.strlen_3a8
[0x000010b0]> s main
[0x00001195]> pdf
/ (fcn) main 261
|   main ();
|           ; var int local_b0h @ rbp-0xb0
|           ; var int local_a8h @ rbp-0xa8
|           ; var int local_a0h @ rbp-0xa0
|           ; var int local_98h @ rbp-0x98
|           ; var int local_90h @ rbp-0x90
|           ; var int local_8eh @ rbp-0x8e
|           ; var int local_80h @ rbp-0x80
|           ; var int local_10h @ rbp-0x10
|           ; var int local_8h @ rbp-0x8
|              ; DATA XREF from 0x000010cd (entry0)
|           0x00001195      55             push rbp
|           0x00001196      4889e5         mov rbp, rsp
|           0x00001199      4881ecb00000.  sub rsp, 0xb0
|           0x000011a0      488d3d610e00.  lea rdi, qword str.Attention_Earthling ; 0x2008 ; "Attention Earthling!" ; const char * s
|           0x000011a7      e884feffff     call sym.imp.puts           ; int puts(const char *s)
|           0x000011ac      bf01000000     mov edi, 1                  ; int s
|           0x000011b1      e8dafeffff     call sym.imp.sleep          ; int sleep(int s)
|           0x000011b6      488d3d600e00.  lea rdi, qword str.To_Enter_Kryptonian_Airspace ; 0x201d ; "To Enter Kryptonian Airspace," ; const char * s
|           0x000011bd      e86efeffff     call sym.imp.puts           ; int puts(const char *s)
|           0x000011c2      bf01000000     mov edi, 1                  ; int s
|           0x000011c7      e8c4feffff     call sym.imp.sleep          ; int sleep(int s)
|           0x000011cc      488d3d6d0e00.  lea rdi, qword str.You_must_a_pre_approved_token: ; 0x2040 ; "You must a pre-approved token: " ; const char * format
|           0x000011d3      b800000000     mov eax, 0
|           0x000011d8      e873feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x000011dd      488b157c2e00.  mov rdx, qword [obj.stdin]  ; rdi ; [0x4060:8]=0 ; FILE *stream
|           0x000011e4      488d4580       lea rax, qword [local_80h]
|           0x000011e8      be64000000     mov esi, 0x64               ; 'd' ; int size
|           0x000011ed      4889c7         mov rdi, rax                ; char *s
|           0x000011f0      e86bfeffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x000011f5      488d4580       lea rax, qword [local_80h]
|           0x000011f9      488945f8       mov qword [local_8h], rax
|           0x000011fd      488b45f8       mov rax, qword [local_8h]
|           0x00001201      4889c7         mov rdi, rax                ; const char * s
|           0x00001204      e89f010000     call sub.strlen_3a8         ; size_t strlen(const char *s)
|           0x00001209      48b8c2c09595.  movabs rax, -0x6d6d383a6a6a3f3e
|           0x00001213      48ba929494c1.  movabs rdx, -0x3d3f3b6a3e6b6b6e
|           0x0000121d      48898550ffff.  mov qword [local_b0h], rax
|           0x00001224      48899558ffff.  mov qword [local_a8h], rdx
|           0x0000122b      48b8c397c892.  movabs rax, -0x6f6b3c6d6d37683d
|           0x00001235      48ba9793c6c7.  movabs rdx, -0x3a376c6b38396c69
|           0x0000123f      48898560ffff.  mov qword [local_a0h], rax
|           0x00001246      48899568ffff.  mov qword [local_98h], rdx
|           0x0000124d      66c78570ffff.  mov word [local_90h], 0xfbfb
|           0x00001256      c68572ffffff.  mov byte [local_8eh], 0xf1
|           0x0000125d      488d8550ffff.  lea rax, qword [local_b0h]
|           0x00001264      488945f0       mov qword [local_10h], rax
|           0x00001268      488d4580       lea rax, qword [local_80h]
|           0x0000126c      4889c6         mov rsi, rax
|           0x0000126f      488d3dea0d00.  lea rdi, qword str.Sending___s__to_air_control ; 0x2060 ; "Sending '%s' to air control\n" ; const char * format
|           0x00001276      b800000000     mov eax, 0
|           0x0000127b      e8d0fdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00001280      488b55f0       mov rdx, qword [local_10h]
|           0x00001284      488b45f8       mov rax, qword [local_8h]
|           0x00001288      4889d6         mov rsi, rdx
|           0x0000128b      4889c7         mov rdi, rax
|           0x0000128e      e807000000     call sub.Checking_each_byte..._29a
|           0x00001293      b800000000     mov eax, 0
|           0x00001298      c9             leave
\           0x00001299      c3             ret
```
Looking at the binary, we can see that, after the program prints out ```Your must a pre-approved token: ``` at address ```0x000011cc```, the program then calls ```sub.Checking_each_byte..._29a``` at address ```0x0000128e```.
