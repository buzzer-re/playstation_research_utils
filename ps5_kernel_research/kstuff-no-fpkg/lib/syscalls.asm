global addr__dynlib_dlsym
use64
section .text.sys_exit exec
global sys_exit
sys_exit:
cmp qword [rel addr__sys_exit], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sys_exit]
lea rdx, [rel addr__sys_exit]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sys_exit]
str__sys_exit:
db "_exit", 0
section .bss.sys_exit
addr__sys_exit:
dq 0
section .text.fork exec
global fork
fork:
cmp qword [rel addr__fork], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fork]
lea rdx, [rel addr__fork]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fork]
str__fork:
db "fork", 0
section .bss.fork
addr__fork:
dq 0
section .text.read exec
global read
read:
cmp qword [rel addr__read], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__read]
lea rdx, [rel addr__read]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__read]
str__read:
db "_read", 0
section .bss.read
addr__read:
dq 0
section .text.write exec
global write
write:
cmp qword [rel addr__write], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__write]
lea rdx, [rel addr__write]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__write]
str__write:
db "_write", 0
section .bss.write
addr__write:
dq 0
section .text.open exec
global open
open:
cmp qword [rel addr__open], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__open]
lea rdx, [rel addr__open]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__open]
str__open:
db "_open", 0
section .bss.open
addr__open:
dq 0
section .text.close exec
global close
close:
cmp qword [rel addr__close], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__close]
lea rdx, [rel addr__close]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__close]
str__close:
db "_close", 0
section .bss.close
addr__close:
dq 0
section .text.wait4 exec
global wait4
wait4:
cmp qword [rel addr__wait4], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__wait4]
lea rdx, [rel addr__wait4]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__wait4]
str__wait4:
db "_wait4", 0
section .bss.wait4
addr__wait4:
dq 0
section .text.link exec
global link
link:
cmp qword [rel addr__link], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__link]
lea rdx, [rel addr__link]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__link]
str__link:
db "link", 0
section .bss.link
addr__link:
dq 0
section .text.unlink exec
global unlink
unlink:
cmp qword [rel addr__unlink], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__unlink]
lea rdx, [rel addr__unlink]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__unlink]
str__unlink:
db "unlink", 0
section .bss.unlink
addr__unlink:
dq 0
section .text.chdir exec
global chdir
chdir:
cmp qword [rel addr__chdir], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__chdir]
lea rdx, [rel addr__chdir]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__chdir]
str__chdir:
db "chdir", 0
section .bss.chdir
addr__chdir:
dq 0
section .text.fchdir exec
global fchdir
fchdir:
cmp qword [rel addr__fchdir], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fchdir]
lea rdx, [rel addr__fchdir]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fchdir]
str__fchdir:
db "fchdir", 0
section .bss.fchdir
addr__fchdir:
dq 0
section .text.chmod exec
global chmod
chmod:
cmp qword [rel addr__chmod], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__chmod]
lea rdx, [rel addr__chmod]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__chmod]
str__chmod:
db "chmod", 0
section .bss.chmod
addr__chmod:
dq 0
section .text.chown exec
global chown
chown:
cmp qword [rel addr__chown], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__chown]
lea rdx, [rel addr__chown]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__chown]
str__chown:
db "chown", 0
section .bss.chown
addr__chown:
dq 0
section .text.getpid exec
global getpid
getpid:
cmp qword [rel addr__getpid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getpid]
lea rdx, [rel addr__getpid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getpid]
str__getpid:
db "getpid", 0
section .bss.getpid
addr__getpid:
dq 0
section .text.mount exec
global mount
mount:
cmp qword [rel addr__mount], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__mount]
lea rdx, [rel addr__mount]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__mount]
str__mount:
db "mount", 0
section .bss.mount
addr__mount:
dq 0
section .text.unmount exec
global unmount
unmount:
cmp qword [rel addr__unmount], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__unmount]
lea rdx, [rel addr__unmount]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__unmount]
str__unmount:
db "unmount", 0
section .bss.unmount
addr__unmount:
dq 0
section .text.setuid exec
global setuid
setuid:
cmp qword [rel addr__setuid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setuid]
lea rdx, [rel addr__setuid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setuid]
str__setuid:
db "setuid", 0
section .bss.setuid
addr__setuid:
dq 0
section .text.getuid exec
global getuid
getuid:
cmp qword [rel addr__getuid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getuid]
lea rdx, [rel addr__getuid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getuid]
str__getuid:
db "getuid", 0
section .bss.getuid
addr__getuid:
dq 0
section .text.geteuid exec
global geteuid
geteuid:
cmp qword [rel addr__geteuid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__geteuid]
lea rdx, [rel addr__geteuid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__geteuid]
str__geteuid:
db "geteuid", 0
section .bss.geteuid
addr__geteuid:
dq 0
section .text.ptrace exec
global ptrace
ptrace:
cmp qword [rel addr__ptrace], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__ptrace]
lea rdx, [rel addr__ptrace]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__ptrace]
str__ptrace:
db "ptrace", 0
section .bss.ptrace
addr__ptrace:
dq 0
section .text.recvmsg exec
global recvmsg
recvmsg:
cmp qword [rel addr__recvmsg], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__recvmsg]
lea rdx, [rel addr__recvmsg]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__recvmsg]
str__recvmsg:
db "_recvmsg", 0
section .bss.recvmsg
addr__recvmsg:
dq 0
section .text.sendmsg exec
global sendmsg
sendmsg:
cmp qword [rel addr__sendmsg], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sendmsg]
lea rdx, [rel addr__sendmsg]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sendmsg]
str__sendmsg:
db "_sendmsg", 0
section .bss.sendmsg
addr__sendmsg:
dq 0
section .text.recvfrom exec
global recvfrom
recvfrom:
cmp qword [rel addr__recvfrom], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__recvfrom]
lea rdx, [rel addr__recvfrom]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__recvfrom]
str__recvfrom:
db "_recvfrom", 0
section .bss.recvfrom
addr__recvfrom:
dq 0
section .text.accept exec
global accept
accept:
cmp qword [rel addr__accept], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__accept]
lea rdx, [rel addr__accept]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__accept]
str__accept:
db "_accept", 0
section .bss.accept
addr__accept:
dq 0
section .text.getpeername exec
global getpeername
getpeername:
cmp qword [rel addr__getpeername], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getpeername]
lea rdx, [rel addr__getpeername]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getpeername]
str__getpeername:
db "_getpeername", 0
section .bss.getpeername
addr__getpeername:
dq 0
section .text.getsockname exec
global getsockname
getsockname:
cmp qword [rel addr__getsockname], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getsockname]
lea rdx, [rel addr__getsockname]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getsockname]
str__getsockname:
db "_getsockname", 0
section .bss.getsockname
addr__getsockname:
dq 0
section .text.access exec
global access
access:
cmp qword [rel addr__access], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__access]
lea rdx, [rel addr__access]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__access]
str__access:
db "access", 0
section .bss.access
addr__access:
dq 0
section .text.chflags exec
global chflags
chflags:
cmp qword [rel addr__chflags], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__chflags]
lea rdx, [rel addr__chflags]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__chflags]
str__chflags:
db "chflags", 0
section .bss.chflags
addr__chflags:
dq 0
section .text.fchflags exec
global fchflags
fchflags:
cmp qword [rel addr__fchflags], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fchflags]
lea rdx, [rel addr__fchflags]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fchflags]
str__fchflags:
db "fchflags", 0
section .bss.fchflags
addr__fchflags:
dq 0
section .text.sync exec
global sync
sync:
cmp qword [rel addr__sync], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sync]
lea rdx, [rel addr__sync]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sync]
str__sync:
db "sync", 0
section .bss.sync
addr__sync:
dq 0
section .text.kill exec
global kill
kill:
cmp qword [rel addr__kill], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__kill]
lea rdx, [rel addr__kill]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__kill]
str__kill:
db "kill", 0
section .bss.kill
addr__kill:
dq 0
section .text.getppid exec
global getppid
getppid:
cmp qword [rel addr__getppid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getppid]
lea rdx, [rel addr__getppid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getppid]
str__getppid:
db "getppid", 0
section .bss.getppid
addr__getppid:
dq 0
section .text.dup exec
global dup
dup:
cmp qword [rel addr__dup], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__dup]
lea rdx, [rel addr__dup]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__dup]
str__dup:
db "dup", 0
section .bss.dup
addr__dup:
dq 0
section .text.pipe exec
global pipe
pipe:
cmp qword [rel addr__pipe], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__pipe]
lea rdx, [rel addr__pipe]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__pipe]
str__pipe:
db "pipe", 0
section .bss.pipe
addr__pipe:
dq 0
section .text.getegid exec
global getegid
getegid:
cmp qword [rel addr__getegid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getegid]
lea rdx, [rel addr__getegid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getegid]
str__getegid:
db "getegid", 0
section .bss.getegid
addr__getegid:
dq 0
section .text.profil exec
global profil
profil:
cmp qword [rel addr__profil], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__profil]
lea rdx, [rel addr__profil]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__profil]
str__profil:
db "profil", 0
section .bss.profil
addr__profil:
dq 0
section .text.ktrace exec
global ktrace
ktrace:
cmp qword [rel addr__ktrace], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__ktrace]
lea rdx, [rel addr__ktrace]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__ktrace]
str__ktrace:
db "ktrace", 0
section .bss.ktrace
addr__ktrace:
dq 0
section .text.getgid exec
global getgid
getgid:
cmp qword [rel addr__getgid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getgid]
lea rdx, [rel addr__getgid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getgid]
str__getgid:
db "getgid", 0
section .bss.getgid
addr__getgid:
dq 0
section .text.getlogin exec
global getlogin
getlogin:
cmp qword [rel addr__getlogin], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getlogin]
lea rdx, [rel addr__getlogin]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getlogin]
str__getlogin:
db "getlogin", 0
section .bss.getlogin
addr__getlogin:
dq 0
section .text.setlogin exec
global setlogin
setlogin:
cmp qword [rel addr__setlogin], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setlogin]
lea rdx, [rel addr__setlogin]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setlogin]
str__setlogin:
db "setlogin", 0
section .bss.setlogin
addr__setlogin:
dq 0
section .text.sigaltstack exec
global sigaltstack
sigaltstack:
cmp qword [rel addr__sigaltstack], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sigaltstack]
lea rdx, [rel addr__sigaltstack]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sigaltstack]
str__sigaltstack:
db "sigaltstack", 0
section .bss.sigaltstack
addr__sigaltstack:
dq 0
section .text.ioctl exec
global ioctl
ioctl:
cmp qword [rel addr__ioctl], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__ioctl]
lea rdx, [rel addr__ioctl]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__ioctl]
str__ioctl:
db "_ioctl", 0
section .bss.ioctl
addr__ioctl:
dq 0
section .text.reboot exec
global reboot
reboot:
cmp qword [rel addr__reboot], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__reboot]
lea rdx, [rel addr__reboot]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__reboot]
str__reboot:
db "reboot", 0
section .bss.reboot
addr__reboot:
dq 0
section .text.revoke exec
global revoke
revoke:
cmp qword [rel addr__revoke], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__revoke]
lea rdx, [rel addr__revoke]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__revoke]
str__revoke:
db "revoke", 0
section .bss.revoke
addr__revoke:
dq 0
section .text.symlink exec
global symlink
symlink:
cmp qword [rel addr__symlink], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__symlink]
lea rdx, [rel addr__symlink]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__symlink]
str__symlink:
db "symlink", 0
section .bss.symlink
addr__symlink:
dq 0
section .text.readlink exec
global readlink
readlink:
cmp qword [rel addr__readlink], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__readlink]
lea rdx, [rel addr__readlink]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__readlink]
str__readlink:
db "readlink", 0
section .bss.readlink
addr__readlink:
dq 0
section .text.execve exec
global execve
execve:
cmp qword [rel addr__execve], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__execve]
lea rdx, [rel addr__execve]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__execve]
str__execve:
db "_execve", 0
section .bss.execve
addr__execve:
dq 0
section .text.umask exec
global umask
umask:
cmp qword [rel addr__umask], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__umask]
lea rdx, [rel addr__umask]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__umask]
str__umask:
db "umask", 0
section .bss.umask
addr__umask:
dq 0
section .text.chroot exec
global chroot
chroot:
cmp qword [rel addr__chroot], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__chroot]
lea rdx, [rel addr__chroot]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__chroot]
str__chroot:
db "chroot", 0
section .bss.chroot
addr__chroot:
dq 0
section .text.msync exec
global msync
msync:
cmp qword [rel addr__msync], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__msync]
lea rdx, [rel addr__msync]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__msync]
str__msync:
db "msync", 0
section .bss.msync
addr__msync:
dq 0
section .text.vfork exec
global vfork
vfork:
cmp qword [rel addr__vfork], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__vfork]
lea rdx, [rel addr__vfork]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__vfork]
str__vfork:
db "vfork", 0
section .bss.vfork
addr__vfork:
dq 0
section .text.munmap exec
global munmap
munmap:
cmp qword [rel addr__munmap], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__munmap]
lea rdx, [rel addr__munmap]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__munmap]
str__munmap:
db "munmap", 0
section .bss.munmap
addr__munmap:
dq 0
section .text.mprotect exec
global mprotect
mprotect:
cmp qword [rel addr__mprotect], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__mprotect]
lea rdx, [rel addr__mprotect]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__mprotect]
str__mprotect:
db "mprotect", 0
section .bss.mprotect
addr__mprotect:
dq 0
section .text.madvise exec
global madvise
madvise:
cmp qword [rel addr__madvise], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__madvise]
lea rdx, [rel addr__madvise]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__madvise]
str__madvise:
db "madvise", 0
section .bss.madvise
addr__madvise:
dq 0
section .text.mincore exec
global mincore
mincore:
cmp qword [rel addr__mincore], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__mincore]
lea rdx, [rel addr__mincore]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__mincore]
str__mincore:
db "mincore", 0
section .bss.mincore
addr__mincore:
dq 0
section .text.getgroups exec
global getgroups
getgroups:
cmp qword [rel addr__getgroups], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getgroups]
lea rdx, [rel addr__getgroups]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getgroups]
str__getgroups:
db "getgroups", 0
section .bss.getgroups
addr__getgroups:
dq 0
section .text.setgroups exec
global setgroups
setgroups:
cmp qword [rel addr__setgroups], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setgroups]
lea rdx, [rel addr__setgroups]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setgroups]
str__setgroups:
db "setgroups", 0
section .bss.setgroups
addr__setgroups:
dq 0
section .text.setpgid exec
global setpgid
setpgid:
cmp qword [rel addr__setpgid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setpgid]
lea rdx, [rel addr__setpgid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setpgid]
str__setpgid:
db "setpgid", 0
section .bss.setpgid
addr__setpgid:
dq 0
section .text.setitimer exec
global setitimer
setitimer:
cmp qword [rel addr__setitimer], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setitimer]
lea rdx, [rel addr__setitimer]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setitimer]
str__setitimer:
db "setitimer", 0
section .bss.setitimer
addr__setitimer:
dq 0
section .text.swapon exec
global swapon
swapon:
cmp qword [rel addr__swapon], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__swapon]
lea rdx, [rel addr__swapon]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__swapon]
str__swapon:
db "swapon", 0
section .bss.swapon
addr__swapon:
dq 0
section .text.getitimer exec
global getitimer
getitimer:
cmp qword [rel addr__getitimer], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getitimer]
lea rdx, [rel addr__getitimer]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getitimer]
str__getitimer:
db "getitimer", 0
section .bss.getitimer
addr__getitimer:
dq 0
section .text.getdtablesize exec
global getdtablesize
getdtablesize:
cmp qword [rel addr__getdtablesize], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getdtablesize]
lea rdx, [rel addr__getdtablesize]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getdtablesize]
str__getdtablesize:
db "getdtablesize", 0
section .bss.getdtablesize
addr__getdtablesize:
dq 0
section .text.dup2 exec
global dup2
dup2:
cmp qword [rel addr__dup2], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__dup2]
lea rdx, [rel addr__dup2]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__dup2]
str__dup2:
db "_dup2", 0
section .bss.dup2
addr__dup2:
dq 0
section .text.fcntl exec
global fcntl
fcntl:
cmp qword [rel addr__fcntl], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fcntl]
lea rdx, [rel addr__fcntl]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fcntl]
str__fcntl:
db "_fcntl", 0
section .bss.fcntl
addr__fcntl:
dq 0
section .text.select exec
global select
select:
cmp qword [rel addr__select], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__select]
lea rdx, [rel addr__select]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__select]
str__select:
db "select", 0
section .bss.select
addr__select:
dq 0
section .text.fsync exec
global fsync
fsync:
cmp qword [rel addr__fsync], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fsync]
lea rdx, [rel addr__fsync]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fsync]
str__fsync:
db "fsync", 0
section .bss.fsync
addr__fsync:
dq 0
section .text.setpriority exec
global setpriority
setpriority:
cmp qword [rel addr__setpriority], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setpriority]
lea rdx, [rel addr__setpriority]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setpriority]
str__setpriority:
db "setpriority", 0
section .bss.setpriority
addr__setpriority:
dq 0
section .text.socket exec
global socket
socket:
cmp qword [rel addr__socket], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__socket]
lea rdx, [rel addr__socket]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__socket]
str__socket:
db "socket", 0
section .bss.socket
addr__socket:
dq 0
section .text.connect exec
global connect
connect:
cmp qword [rel addr__connect], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__connect]
lea rdx, [rel addr__connect]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__connect]
str__connect:
db "_connect", 0
section .bss.connect
addr__connect:
dq 0
section .text.netcontrol exec
global netcontrol
netcontrol:
cmp qword [rel addr__netcontrol], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__netcontrol]
lea rdx, [rel addr__netcontrol]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__netcontrol]
str__netcontrol:
db "__sys_netcontrol", 0
section .bss.netcontrol
addr__netcontrol:
dq 0
section .text.getpriority exec
global getpriority
getpriority:
cmp qword [rel addr__getpriority], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getpriority]
lea rdx, [rel addr__getpriority]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getpriority]
str__getpriority:
db "getpriority", 0
section .bss.getpriority
addr__getpriority:
dq 0
section .text.netabort exec
global netabort
netabort:
cmp qword [rel addr__netabort], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__netabort]
lea rdx, [rel addr__netabort]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__netabort]
str__netabort:
db "__sys_netabort", 0
section .bss.netabort
addr__netabort:
dq 0
section .text.netgetsockinfo exec
global netgetsockinfo
netgetsockinfo:
cmp qword [rel addr__netgetsockinfo], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__netgetsockinfo]
lea rdx, [rel addr__netgetsockinfo]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__netgetsockinfo]
str__netgetsockinfo:
db "__sys_netgetsockinfo", 0
section .bss.netgetsockinfo
addr__netgetsockinfo:
dq 0
section .text.bind exec
global bind
bind:
cmp qword [rel addr__bind], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__bind]
lea rdx, [rel addr__bind]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__bind]
str__bind:
db "_bind", 0
section .bss.bind
addr__bind:
dq 0
section .text.setsockopt exec
global setsockopt
setsockopt:
cmp qword [rel addr__setsockopt], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setsockopt]
lea rdx, [rel addr__setsockopt]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setsockopt]
str__setsockopt:
db "_setsockopt", 0
section .bss.setsockopt
addr__setsockopt:
dq 0
section .text.listen exec
global listen
listen:
cmp qword [rel addr__listen], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__listen]
lea rdx, [rel addr__listen]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__listen]
str__listen:
db "_listen", 0
section .bss.listen
addr__listen:
dq 0
section .text.socketex exec
global socketex
socketex:
cmp qword [rel addr__socketex], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__socketex]
lea rdx, [rel addr__socketex]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__socketex]
str__socketex:
db "__sys_socketex", 0
section .bss.socketex
addr__socketex:
dq 0
section .text.socketclose exec
global socketclose
socketclose:
cmp qword [rel addr__socketclose], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__socketclose]
lea rdx, [rel addr__socketclose]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__socketclose]
str__socketclose:
db "__sys_socketclose", 0
section .bss.socketclose
addr__socketclose:
dq 0
section .text.gettimeofday exec
global gettimeofday
gettimeofday:
cmp qword [rel addr__gettimeofday], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__gettimeofday]
lea rdx, [rel addr__gettimeofday]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__gettimeofday]
str__gettimeofday:
db "gettimeofday", 0
section .bss.gettimeofday
addr__gettimeofday:
dq 0
section .text.getrusage exec
global getrusage
getrusage:
cmp qword [rel addr__getrusage], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getrusage]
lea rdx, [rel addr__getrusage]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getrusage]
str__getrusage:
db "getrusage", 0
section .bss.getrusage
addr__getrusage:
dq 0
section .text.getsockopt exec
global getsockopt
getsockopt:
cmp qword [rel addr__getsockopt], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getsockopt]
lea rdx, [rel addr__getsockopt]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getsockopt]
str__getsockopt:
db "_getsockopt", 0
section .bss.getsockopt
addr__getsockopt:
dq 0
section .text.readv exec
global readv
readv:
cmp qword [rel addr__readv], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__readv]
lea rdx, [rel addr__readv]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__readv]
str__readv:
db "_readv", 0
section .bss.readv
addr__readv:
dq 0
section .text.writev exec
global writev
writev:
cmp qword [rel addr__writev], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__writev]
lea rdx, [rel addr__writev]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__writev]
str__writev:
db "_writev", 0
section .bss.writev
addr__writev:
dq 0
section .text.settimeofday exec
global settimeofday
settimeofday:
cmp qword [rel addr__settimeofday], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__settimeofday]
lea rdx, [rel addr__settimeofday]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__settimeofday]
str__settimeofday:
db "settimeofday", 0
section .bss.settimeofday
addr__settimeofday:
dq 0
section .text.fchown exec
global fchown
fchown:
cmp qword [rel addr__fchown], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fchown]
lea rdx, [rel addr__fchown]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fchown]
str__fchown:
db "fchown", 0
section .bss.fchown
addr__fchown:
dq 0
section .text.fchmod exec
global fchmod
fchmod:
cmp qword [rel addr__fchmod], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fchmod]
lea rdx, [rel addr__fchmod]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fchmod]
str__fchmod:
db "fchmod", 0
section .bss.fchmod
addr__fchmod:
dq 0
section .text.netgetiflist exec
global netgetiflist
netgetiflist:
cmp qword [rel addr__netgetiflist], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__netgetiflist]
lea rdx, [rel addr__netgetiflist]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__netgetiflist]
str__netgetiflist:
db "__sys_netgetiflist", 0
section .bss.netgetiflist
addr__netgetiflist:
dq 0
section .text.setreuid exec
global setreuid
setreuid:
cmp qword [rel addr__setreuid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setreuid]
lea rdx, [rel addr__setreuid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setreuid]
str__setreuid:
db "setreuid", 0
section .bss.setreuid
addr__setreuid:
dq 0
section .text.setregid exec
global setregid
setregid:
cmp qword [rel addr__setregid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setregid]
lea rdx, [rel addr__setregid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setregid]
str__setregid:
db "setregid", 0
section .bss.setregid
addr__setregid:
dq 0
section .text.rename exec
global rename
rename:
cmp qword [rel addr__rename], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__rename]
lea rdx, [rel addr__rename]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__rename]
str__rename:
db "rename", 0
section .bss.rename
addr__rename:
dq 0
section .text.flock exec
global flock
flock:
cmp qword [rel addr__flock], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__flock]
lea rdx, [rel addr__flock]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__flock]
str__flock:
db "flock", 0
section .bss.flock
addr__flock:
dq 0
section .text.sendto exec
global sendto
sendto:
cmp qword [rel addr__sendto], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sendto]
lea rdx, [rel addr__sendto]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sendto]
str__sendto:
db "_sendto", 0
section .bss.sendto
addr__sendto:
dq 0
section .text.shutdown exec
global shutdown
shutdown:
cmp qword [rel addr__shutdown], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__shutdown]
lea rdx, [rel addr__shutdown]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__shutdown]
str__shutdown:
db "shutdown", 0
section .bss.shutdown
addr__shutdown:
dq 0
section .text.socketpair exec
global socketpair
socketpair:
cmp qword [rel addr__socketpair], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__socketpair]
lea rdx, [rel addr__socketpair]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__socketpair]
str__socketpair:
db "socketpair", 0
section .bss.socketpair
addr__socketpair:
dq 0
section .text.mkdir exec
global mkdir
mkdir:
cmp qword [rel addr__mkdir], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__mkdir]
lea rdx, [rel addr__mkdir]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__mkdir]
str__mkdir:
db "mkdir", 0
section .bss.mkdir
addr__mkdir:
dq 0
section .text.rmdir exec
global rmdir
rmdir:
cmp qword [rel addr__rmdir], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__rmdir]
lea rdx, [rel addr__rmdir]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__rmdir]
str__rmdir:
db "rmdir", 0
section .bss.rmdir
addr__rmdir:
dq 0
section .text.utimes exec
global utimes
utimes:
cmp qword [rel addr__utimes], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__utimes]
lea rdx, [rel addr__utimes]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__utimes]
str__utimes:
db "utimes", 0
section .bss.utimes
addr__utimes:
dq 0
section .text.kqueueex exec
global kqueueex
kqueueex:
cmp qword [rel addr__kqueueex], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__kqueueex]
lea rdx, [rel addr__kqueueex]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__kqueueex]
str__kqueueex:
db "__sys_kqueueex", 0
section .bss.kqueueex
addr__kqueueex:
dq 0
section .text.setsid exec
global setsid
setsid:
cmp qword [rel addr__setsid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setsid]
lea rdx, [rel addr__setsid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setsid]
str__setsid:
db "setsid", 0
section .bss.setsid
addr__setsid:
dq 0
section .text.sysarch exec
global sysarch
sysarch:
cmp qword [rel addr__sysarch], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sysarch]
lea rdx, [rel addr__sysarch]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sysarch]
str__sysarch:
db "sysarch", 0
section .bss.sysarch
addr__sysarch:
dq 0
section .text.setegid exec
global setegid
setegid:
cmp qword [rel addr__setegid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setegid]
lea rdx, [rel addr__setegid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setegid]
str__setegid:
db "setegid", 0
section .bss.setegid
addr__setegid:
dq 0
section .text.seteuid exec
global seteuid
seteuid:
cmp qword [rel addr__seteuid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__seteuid]
lea rdx, [rel addr__seteuid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__seteuid]
str__seteuid:
db "seteuid", 0
section .bss.seteuid
addr__seteuid:
dq 0
section .text.stat exec
global stat
stat:
cmp qword [rel addr__stat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__stat]
lea rdx, [rel addr__stat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__stat]
str__stat:
db "stat", 0
section .bss.stat
addr__stat:
dq 0
section .text.fstat exec
global fstat
fstat:
cmp qword [rel addr__fstat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fstat]
lea rdx, [rel addr__fstat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fstat]
str__fstat:
db "_fstat", 0
section .bss.fstat
addr__fstat:
dq 0
section .text.lstat exec
global lstat
lstat:
cmp qword [rel addr__lstat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__lstat]
lea rdx, [rel addr__lstat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__lstat]
str__lstat:
db "lstat", 0
section .bss.lstat
addr__lstat:
dq 0
section .text.pathconf exec
global pathconf
pathconf:
cmp qword [rel addr__pathconf], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__pathconf]
lea rdx, [rel addr__pathconf]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__pathconf]
str__pathconf:
db "pathconf", 0
section .bss.pathconf
addr__pathconf:
dq 0
section .text.fpathconf exec
global fpathconf
fpathconf:
cmp qword [rel addr__fpathconf], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fpathconf]
lea rdx, [rel addr__fpathconf]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fpathconf]
str__fpathconf:
db "_fpathconf", 0
section .bss.fpathconf
addr__fpathconf:
dq 0
section .text.getrlimit exec
global getrlimit
getrlimit:
cmp qword [rel addr__getrlimit], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getrlimit]
lea rdx, [rel addr__getrlimit]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getrlimit]
str__getrlimit:
db "getrlimit", 0
section .bss.getrlimit
addr__getrlimit:
dq 0
section .text.setrlimit exec
global setrlimit
setrlimit:
cmp qword [rel addr__setrlimit], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setrlimit]
lea rdx, [rel addr__setrlimit]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setrlimit]
str__setrlimit:
db "setrlimit", 0
section .bss.setrlimit
addr__setrlimit:
dq 0
section .text.getdirentries exec
global getdirentries
getdirentries:
cmp qword [rel addr__getdirentries], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getdirentries]
lea rdx, [rel addr__getdirentries]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getdirentries]
str__getdirentries:
db "_getdirentries", 0
section .bss.getdirentries
addr__getdirentries:
dq 0
section .text.__sysctl exec
global __sysctl
__sysctl:
cmp qword [rel addr____sysctl], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str____sysctl]
lea rdx, [rel addr____sysctl]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr____sysctl]
str____sysctl:
db "sysctl", 0
section .bss.__sysctl
addr____sysctl:
dq 0
section .text.mlock exec
global mlock
mlock:
cmp qword [rel addr__mlock], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__mlock]
lea rdx, [rel addr__mlock]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__mlock]
str__mlock:
db "mlock", 0
section .bss.mlock
addr__mlock:
dq 0
section .text.munlock exec
global munlock
munlock:
cmp qword [rel addr__munlock], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__munlock]
lea rdx, [rel addr__munlock]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__munlock]
str__munlock:
db "munlock", 0
section .bss.munlock
addr__munlock:
dq 0
section .text.futimes exec
global futimes
futimes:
cmp qword [rel addr__futimes], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__futimes]
lea rdx, [rel addr__futimes]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__futimes]
str__futimes:
db "futimes", 0
section .bss.futimes
addr__futimes:
dq 0
section .text.poll exec
global poll
poll:
cmp qword [rel addr__poll], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__poll]
lea rdx, [rel addr__poll]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__poll]
str__poll:
db "poll", 0
section .bss.poll
addr__poll:
dq 0
section .text.clock_gettime exec
global clock_gettime
clock_gettime:
cmp qword [rel addr__clock_gettime], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__clock_gettime]
lea rdx, [rel addr__clock_gettime]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__clock_gettime]
str__clock_gettime:
db "clock_gettime", 0
section .bss.clock_gettime
addr__clock_gettime:
dq 0
section .text.clock_settime exec
global clock_settime
clock_settime:
cmp qword [rel addr__clock_settime], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__clock_settime]
lea rdx, [rel addr__clock_settime]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__clock_settime]
str__clock_settime:
db "clock_settime", 0
section .bss.clock_settime
addr__clock_settime:
dq 0
section .text.clock_getres exec
global clock_getres
clock_getres:
cmp qword [rel addr__clock_getres], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__clock_getres]
lea rdx, [rel addr__clock_getres]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__clock_getres]
str__clock_getres:
db "clock_getres", 0
section .bss.clock_getres
addr__clock_getres:
dq 0
section .text.ktimer_create exec
global ktimer_create
ktimer_create:
cmp qword [rel addr__ktimer_create], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__ktimer_create]
lea rdx, [rel addr__ktimer_create]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__ktimer_create]
str__ktimer_create:
db "ktimer_create", 0
section .bss.ktimer_create
addr__ktimer_create:
dq 0
section .text.ktimer_delete exec
global ktimer_delete
ktimer_delete:
cmp qword [rel addr__ktimer_delete], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__ktimer_delete]
lea rdx, [rel addr__ktimer_delete]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__ktimer_delete]
str__ktimer_delete:
db "ktimer_delete", 0
section .bss.ktimer_delete
addr__ktimer_delete:
dq 0
section .text.ktimer_settime exec
global ktimer_settime
ktimer_settime:
cmp qword [rel addr__ktimer_settime], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__ktimer_settime]
lea rdx, [rel addr__ktimer_settime]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__ktimer_settime]
str__ktimer_settime:
db "ktimer_settime", 0
section .bss.ktimer_settime
addr__ktimer_settime:
dq 0
section .text.ktimer_gettime exec
global ktimer_gettime
ktimer_gettime:
cmp qword [rel addr__ktimer_gettime], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__ktimer_gettime]
lea rdx, [rel addr__ktimer_gettime]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__ktimer_gettime]
str__ktimer_gettime:
db "ktimer_gettime", 0
section .bss.ktimer_gettime
addr__ktimer_gettime:
dq 0
section .text.ktimer_getoverrun exec
global ktimer_getoverrun
ktimer_getoverrun:
cmp qword [rel addr__ktimer_getoverrun], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__ktimer_getoverrun]
lea rdx, [rel addr__ktimer_getoverrun]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__ktimer_getoverrun]
str__ktimer_getoverrun:
db "ktimer_getoverrun", 0
section .bss.ktimer_getoverrun
addr__ktimer_getoverrun:
dq 0
section .text.nanosleep exec
global nanosleep
nanosleep:
cmp qword [rel addr__nanosleep], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__nanosleep]
lea rdx, [rel addr__nanosleep]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__nanosleep]
str__nanosleep:
db "_nanosleep", 0
section .bss.nanosleep
addr__nanosleep:
dq 0
section .text.issetugid exec
global issetugid
issetugid:
cmp qword [rel addr__issetugid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__issetugid]
lea rdx, [rel addr__issetugid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__issetugid]
str__issetugid:
db "issetugid", 0
section .bss.issetugid
addr__issetugid:
dq 0
section .text.lchown exec
global lchown
lchown:
cmp qword [rel addr__lchown], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__lchown]
lea rdx, [rel addr__lchown]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__lchown]
str__lchown:
db "lchown", 0
section .bss.lchown
addr__lchown:
dq 0
section .text.getdents exec
global getdents
getdents:
cmp qword [rel addr__getdents], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getdents]
lea rdx, [rel addr__getdents]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getdents]
str__getdents:
db "getdents", 0
section .bss.getdents
addr__getdents:
dq 0
section .text.lchmod exec
global lchmod
lchmod:
cmp qword [rel addr__lchmod], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__lchmod]
lea rdx, [rel addr__lchmod]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__lchmod]
str__lchmod:
db "lchmod", 0
section .bss.lchmod
addr__lchmod:
dq 0
section .text.lutimes exec
global lutimes
lutimes:
cmp qword [rel addr__lutimes], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__lutimes]
lea rdx, [rel addr__lutimes]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__lutimes]
str__lutimes:
db "lutimes", 0
section .bss.lutimes
addr__lutimes:
dq 0
section .text.preadv exec
global preadv
preadv:
cmp qword [rel addr__preadv], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__preadv]
lea rdx, [rel addr__preadv]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__preadv]
str__preadv:
db "preadv", 0
section .bss.preadv
addr__preadv:
dq 0
section .text.pwritev exec
global pwritev
pwritev:
cmp qword [rel addr__pwritev], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__pwritev]
lea rdx, [rel addr__pwritev]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__pwritev]
str__pwritev:
db "pwritev", 0
section .bss.pwritev
addr__pwritev:
dq 0
section .text.kldload exec
global kldload
kldload:
cmp qword [rel addr__kldload], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__kldload]
lea rdx, [rel addr__kldload]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__kldload]
str__kldload:
db "kldload", 0
section .bss.kldload
addr__kldload:
dq 0
section .text.kldunload exec
global kldunload
kldunload:
cmp qword [rel addr__kldunload], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__kldunload]
lea rdx, [rel addr__kldunload]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__kldunload]
str__kldunload:
db "kldunload", 0
section .bss.kldunload
addr__kldunload:
dq 0
section .text.kldfind exec
global kldfind
kldfind:
cmp qword [rel addr__kldfind], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__kldfind]
lea rdx, [rel addr__kldfind]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__kldfind]
str__kldfind:
db "kldfind", 0
section .bss.kldfind
addr__kldfind:
dq 0
section .text.kldnext exec
global kldnext
kldnext:
cmp qword [rel addr__kldnext], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__kldnext]
lea rdx, [rel addr__kldnext]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__kldnext]
str__kldnext:
db "kldnext", 0
section .bss.kldnext
addr__kldnext:
dq 0
section .text.kldstat exec
global kldstat
kldstat:
cmp qword [rel addr__kldstat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__kldstat]
lea rdx, [rel addr__kldstat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__kldstat]
str__kldstat:
db "kldstat", 0
section .bss.kldstat
addr__kldstat:
dq 0
section .text.kldfirstmod exec
global kldfirstmod
kldfirstmod:
cmp qword [rel addr__kldfirstmod], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__kldfirstmod]
lea rdx, [rel addr__kldfirstmod]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__kldfirstmod]
str__kldfirstmod:
db "kldfirstmod", 0
section .bss.kldfirstmod
addr__kldfirstmod:
dq 0
section .text.getsid exec
global getsid
getsid:
cmp qword [rel addr__getsid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getsid]
lea rdx, [rel addr__getsid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getsid]
str__getsid:
db "getsid", 0
section .bss.getsid
addr__getsid:
dq 0
section .text.mlockall exec
global mlockall
mlockall:
cmp qword [rel addr__mlockall], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__mlockall]
lea rdx, [rel addr__mlockall]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__mlockall]
str__mlockall:
db "mlockall", 0
section .bss.mlockall
addr__mlockall:
dq 0
section .text.munlockall exec
global munlockall
munlockall:
cmp qword [rel addr__munlockall], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__munlockall]
lea rdx, [rel addr__munlockall]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__munlockall]
str__munlockall:
db "munlockall", 0
section .bss.munlockall
addr__munlockall:
dq 0
section .text.__getcwd exec
global __getcwd
__getcwd:
cmp qword [rel addr____getcwd], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str____getcwd]
lea rdx, [rel addr____getcwd]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr____getcwd]
str____getcwd:
db "__getcwd", 0
section .bss.__getcwd
addr____getcwd:
dq 0
section .text.sched_setparam exec
global sched_setparam
sched_setparam:
cmp qword [rel addr__sched_setparam], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sched_setparam]
lea rdx, [rel addr__sched_setparam]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sched_setparam]
str__sched_setparam:
db "sched_setparam", 0
section .bss.sched_setparam
addr__sched_setparam:
dq 0
section .text.sched_getparam exec
global sched_getparam
sched_getparam:
cmp qword [rel addr__sched_getparam], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sched_getparam]
lea rdx, [rel addr__sched_getparam]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sched_getparam]
str__sched_getparam:
db "sched_getparam", 0
section .bss.sched_getparam
addr__sched_getparam:
dq 0
section .text.sched_setscheduler exec
global sched_setscheduler
sched_setscheduler:
cmp qword [rel addr__sched_setscheduler], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sched_setscheduler]
lea rdx, [rel addr__sched_setscheduler]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sched_setscheduler]
str__sched_setscheduler:
db "sched_setscheduler", 0
section .bss.sched_setscheduler
addr__sched_setscheduler:
dq 0
section .text.sched_getscheduler exec
global sched_getscheduler
sched_getscheduler:
cmp qword [rel addr__sched_getscheduler], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sched_getscheduler]
lea rdx, [rel addr__sched_getscheduler]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sched_getscheduler]
str__sched_getscheduler:
db "sched_getscheduler", 0
section .bss.sched_getscheduler
addr__sched_getscheduler:
dq 0
section .text.sched_yield exec
global sched_yield
sched_yield:
cmp qword [rel addr__sched_yield], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sched_yield]
lea rdx, [rel addr__sched_yield]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sched_yield]
str__sched_yield:
db "sched_yield", 0
section .bss.sched_yield
addr__sched_yield:
dq 0
section .text.sched_get_priority_max exec
global sched_get_priority_max
sched_get_priority_max:
cmp qword [rel addr__sched_get_priority_max], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sched_get_priority_max]
lea rdx, [rel addr__sched_get_priority_max]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sched_get_priority_max]
str__sched_get_priority_max:
db "sched_get_priority_max", 0
section .bss.sched_get_priority_max
addr__sched_get_priority_max:
dq 0
section .text.sched_get_priority_min exec
global sched_get_priority_min
sched_get_priority_min:
cmp qword [rel addr__sched_get_priority_min], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sched_get_priority_min]
lea rdx, [rel addr__sched_get_priority_min]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sched_get_priority_min]
str__sched_get_priority_min:
db "sched_get_priority_min", 0
section .bss.sched_get_priority_min
addr__sched_get_priority_min:
dq 0
section .text.sched_rr_get_interval exec
global sched_rr_get_interval
sched_rr_get_interval:
cmp qword [rel addr__sched_rr_get_interval], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sched_rr_get_interval]
lea rdx, [rel addr__sched_rr_get_interval]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sched_rr_get_interval]
str__sched_rr_get_interval:
db "sched_rr_get_interval", 0
section .bss.sched_rr_get_interval
addr__sched_rr_get_interval:
dq 0
section .text.utrace exec
global utrace
utrace:
cmp qword [rel addr__utrace], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__utrace]
lea rdx, [rel addr__utrace]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__utrace]
str__utrace:
db "utrace", 0
section .bss.utrace
addr__utrace:
dq 0
section .text.kldsym exec
global kldsym
kldsym:
cmp qword [rel addr__kldsym], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__kldsym]
lea rdx, [rel addr__kldsym]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__kldsym]
str__kldsym:
db "kldsym", 0
section .bss.kldsym
addr__kldsym:
dq 0
section .text.sigprocmask exec
global sigprocmask
sigprocmask:
cmp qword [rel addr__sigprocmask], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sigprocmask]
lea rdx, [rel addr__sigprocmask]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sigprocmask]
str__sigprocmask:
db "_sigprocmask", 0
section .bss.sigprocmask
addr__sigprocmask:
dq 0
section .text.sigsuspend exec
global sigsuspend
sigsuspend:
cmp qword [rel addr__sigsuspend], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sigsuspend]
lea rdx, [rel addr__sigsuspend]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sigsuspend]
str__sigsuspend:
db "_sigsuspend", 0
section .bss.sigsuspend
addr__sigsuspend:
dq 0
section .text.sigpending exec
global sigpending
sigpending:
cmp qword [rel addr__sigpending], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sigpending]
lea rdx, [rel addr__sigpending]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sigpending]
str__sigpending:
db "sigpending", 0
section .bss.sigpending
addr__sigpending:
dq 0
section .text.sigtimedwait exec
global sigtimedwait
sigtimedwait:
cmp qword [rel addr__sigtimedwait], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sigtimedwait]
lea rdx, [rel addr__sigtimedwait]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sigtimedwait]
str__sigtimedwait:
db "sigtimedwait", 0
section .bss.sigtimedwait
addr__sigtimedwait:
dq 0
section .text.sigwaitinfo exec
global sigwaitinfo
sigwaitinfo:
cmp qword [rel addr__sigwaitinfo], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sigwaitinfo]
lea rdx, [rel addr__sigwaitinfo]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sigwaitinfo]
str__sigwaitinfo:
db "sigwaitinfo", 0
section .bss.sigwaitinfo
addr__sigwaitinfo:
dq 0
section .text.kqueue exec
global kqueue
kqueue:
cmp qword [rel addr__kqueue], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__kqueue]
lea rdx, [rel addr__kqueue]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__kqueue]
str__kqueue:
db "kqueue", 0
section .bss.kqueue
addr__kqueue:
dq 0
section .text.kevent exec
global kevent
kevent:
cmp qword [rel addr__kevent], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__kevent]
lea rdx, [rel addr__kevent]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__kevent]
str__kevent:
db "kevent", 0
section .bss.kevent
addr__kevent:
dq 0
section .text.nmount exec
global nmount
nmount:
cmp qword [rel addr__nmount], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__nmount]
lea rdx, [rel addr__nmount]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__nmount]
str__nmount:
db "nmount", 0
section .bss.nmount
addr__nmount:
dq 0
section .text.kenv exec
global kenv
kenv:
cmp qword [rel addr__kenv], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__kenv]
lea rdx, [rel addr__kenv]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__kenv]
str__kenv:
db "kenv", 0
section .bss.kenv
addr__kenv:
dq 0
section .text.lchflags exec
global lchflags
lchflags:
cmp qword [rel addr__lchflags], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__lchflags]
lea rdx, [rel addr__lchflags]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__lchflags]
str__lchflags:
db "lchflags", 0
section .bss.lchflags
addr__lchflags:
dq 0
section .text.uuidgen exec
global uuidgen
uuidgen:
cmp qword [rel addr__uuidgen], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__uuidgen]
lea rdx, [rel addr__uuidgen]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__uuidgen]
str__uuidgen:
db "uuidgen", 0
section .bss.uuidgen
addr__uuidgen:
dq 0
section .text.sendfile exec
global sendfile
sendfile:
cmp qword [rel addr__sendfile], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sendfile]
lea rdx, [rel addr__sendfile]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sendfile]
str__sendfile:
db "sendfile", 0
section .bss.sendfile
addr__sendfile:
dq 0
section .text.getfsstat exec
global getfsstat
getfsstat:
cmp qword [rel addr__getfsstat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getfsstat]
lea rdx, [rel addr__getfsstat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getfsstat]
str__getfsstat:
db "getfsstat", 0
section .bss.getfsstat
addr__getfsstat:
dq 0
section .text.statfs exec
global statfs
statfs:
cmp qword [rel addr__statfs], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__statfs]
lea rdx, [rel addr__statfs]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__statfs]
str__statfs:
db "statfs", 0
section .bss.statfs
addr__statfs:
dq 0
section .text.fstatfs exec
global fstatfs
fstatfs:
cmp qword [rel addr__fstatfs], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fstatfs]
lea rdx, [rel addr__fstatfs]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fstatfs]
str__fstatfs:
db "_fstatfs", 0
section .bss.fstatfs
addr__fstatfs:
dq 0
section .text.sigaction exec
global sigaction
sigaction:
cmp qword [rel addr__sigaction], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sigaction]
lea rdx, [rel addr__sigaction]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sigaction]
str__sigaction:
db "_sigaction", 0
section .bss.sigaction
addr__sigaction:
dq 0
section .text.sigreturn exec
global sigreturn
sigreturn:
cmp qword [rel addr__sigreturn], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sigreturn]
lea rdx, [rel addr__sigreturn]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sigreturn]
str__sigreturn:
db "sigreturn", 0
section .bss.sigreturn
addr__sigreturn:
dq 0
section .text.getcontext exec
global getcontext
getcontext:
cmp qword [rel addr__getcontext], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__getcontext]
lea rdx, [rel addr__getcontext]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__getcontext]
str__getcontext:
db "getcontext", 0
section .bss.getcontext
addr__getcontext:
dq 0
section .text.setcontext exec
global setcontext
setcontext:
cmp qword [rel addr__setcontext], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__setcontext]
lea rdx, [rel addr__setcontext]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__setcontext]
str__setcontext:
db "setcontext", 0
section .bss.setcontext
addr__setcontext:
dq 0
section .text.swapcontext exec
global swapcontext
swapcontext:
cmp qword [rel addr__swapcontext], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__swapcontext]
lea rdx, [rel addr__swapcontext]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__swapcontext]
str__swapcontext:
db "swapcontext", 0
section .bss.swapcontext
addr__swapcontext:
dq 0
section .text.sigwait exec
global sigwait
sigwait:
cmp qword [rel addr__sigwait], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sigwait]
lea rdx, [rel addr__sigwait]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sigwait]
str__sigwait:
db "sigwait", 0
section .bss.sigwait
addr__sigwait:
dq 0
section .text._umtx_op exec
global _umtx_op
_umtx_op:
cmp qword [rel addr___umtx_op], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str___umtx_op]
lea rdx, [rel addr___umtx_op]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr___umtx_op]
str___umtx_op:
db "_umtx_op", 0
section .bss._umtx_op
addr___umtx_op:
dq 0
section .text.sigqueue exec
global sigqueue
sigqueue:
cmp qword [rel addr__sigqueue], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sigqueue]
lea rdx, [rel addr__sigqueue]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sigqueue]
str__sigqueue:
db "sigqueue", 0
section .bss.sigqueue
addr__sigqueue:
dq 0
section .text.rtprio_thread exec
global rtprio_thread
rtprio_thread:
cmp qword [rel addr__rtprio_thread], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__rtprio_thread]
lea rdx, [rel addr__rtprio_thread]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__rtprio_thread]
str__rtprio_thread:
db "rtprio_thread", 0
section .bss.rtprio_thread
addr__rtprio_thread:
dq 0
section .text.pread exec
global pread
pread:
cmp qword [rel addr__pread], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__pread]
lea rdx, [rel addr__pread]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__pread]
str__pread:
db "pread", 0
section .bss.pread
addr__pread:
dq 0
section .text.pwrite exec
global pwrite
pwrite:
cmp qword [rel addr__pwrite], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__pwrite]
lea rdx, [rel addr__pwrite]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__pwrite]
str__pwrite:
db "pwrite", 0
section .bss.pwrite
addr__pwrite:
dq 0
section .text.mmap exec
global mmap
mmap:
cmp qword [rel addr__mmap], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__mmap]
lea rdx, [rel addr__mmap]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__mmap]
str__mmap:
db "mmap", 0
section .bss.mmap
addr__mmap:
dq 0
section .text.lseek exec
global lseek
lseek:
cmp qword [rel addr__lseek], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__lseek]
lea rdx, [rel addr__lseek]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__lseek]
str__lseek:
db "lseek", 0
section .bss.lseek
addr__lseek:
dq 0
section .text.truncate exec
global truncate
truncate:
cmp qword [rel addr__truncate], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__truncate]
lea rdx, [rel addr__truncate]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__truncate]
str__truncate:
db "truncate", 0
section .bss.truncate
addr__truncate:
dq 0
section .text.ftruncate exec
global ftruncate
ftruncate:
cmp qword [rel addr__ftruncate], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__ftruncate]
lea rdx, [rel addr__ftruncate]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__ftruncate]
str__ftruncate:
db "ftruncate", 0
section .bss.ftruncate
addr__ftruncate:
dq 0
section .text.shm_open exec
global shm_open
shm_open:
cmp qword [rel addr__shm_open], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__shm_open]
lea rdx, [rel addr__shm_open]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__shm_open]
str__shm_open:
db "shm_open", 0
section .bss.shm_open
addr__shm_open:
dq 0
section .text.shm_unlink exec
global shm_unlink
shm_unlink:
cmp qword [rel addr__shm_unlink], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__shm_unlink]
lea rdx, [rel addr__shm_unlink]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__shm_unlink]
str__shm_unlink:
db "shm_unlink", 0
section .bss.shm_unlink
addr__shm_unlink:
dq 0
section .text.cpuset exec
global cpuset
cpuset:
cmp qword [rel addr__cpuset], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__cpuset]
lea rdx, [rel addr__cpuset]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__cpuset]
str__cpuset:
db "cpuset", 0
section .bss.cpuset
addr__cpuset:
dq 0
section .text.cpuset_setid exec
global cpuset_setid
cpuset_setid:
cmp qword [rel addr__cpuset_setid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__cpuset_setid]
lea rdx, [rel addr__cpuset_setid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__cpuset_setid]
str__cpuset_setid:
db "cpuset_setid", 0
section .bss.cpuset_setid
addr__cpuset_setid:
dq 0
section .text.cpuset_getid exec
global cpuset_getid
cpuset_getid:
cmp qword [rel addr__cpuset_getid], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__cpuset_getid]
lea rdx, [rel addr__cpuset_getid]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__cpuset_getid]
str__cpuset_getid:
db "cpuset_getid", 0
section .bss.cpuset_getid
addr__cpuset_getid:
dq 0
section .text.cpuset_getaffinity exec
global cpuset_getaffinity
cpuset_getaffinity:
cmp qword [rel addr__cpuset_getaffinity], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__cpuset_getaffinity]
lea rdx, [rel addr__cpuset_getaffinity]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__cpuset_getaffinity]
str__cpuset_getaffinity:
db "cpuset_getaffinity", 0
section .bss.cpuset_getaffinity
addr__cpuset_getaffinity:
dq 0
section .text.cpuset_setaffinity exec
global cpuset_setaffinity
cpuset_setaffinity:
cmp qword [rel addr__cpuset_setaffinity], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__cpuset_setaffinity]
lea rdx, [rel addr__cpuset_setaffinity]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__cpuset_setaffinity]
str__cpuset_setaffinity:
db "cpuset_setaffinity", 0
section .bss.cpuset_setaffinity
addr__cpuset_setaffinity:
dq 0
section .text.fchmodat exec
global fchmodat
fchmodat:
cmp qword [rel addr__fchmodat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fchmodat]
lea rdx, [rel addr__fchmodat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fchmodat]
str__fchmodat:
db "fchmodat", 0
section .bss.fchmodat
addr__fchmodat:
dq 0
section .text.fchownat exec
global fchownat
fchownat:
cmp qword [rel addr__fchownat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fchownat]
lea rdx, [rel addr__fchownat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fchownat]
str__fchownat:
db "fchownat", 0
section .bss.fchownat
addr__fchownat:
dq 0
section .text.fstatat exec
global fstatat
fstatat:
cmp qword [rel addr__fstatat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fstatat]
lea rdx, [rel addr__fstatat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fstatat]
str__fstatat:
db "fstatat", 0
section .bss.fstatat
addr__fstatat:
dq 0
section .text.futimesat exec
global futimesat
futimesat:
cmp qword [rel addr__futimesat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__futimesat]
lea rdx, [rel addr__futimesat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__futimesat]
str__futimesat:
db "futimesat", 0
section .bss.futimesat
addr__futimesat:
dq 0
section .text.linkat exec
global linkat
linkat:
cmp qword [rel addr__linkat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__linkat]
lea rdx, [rel addr__linkat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__linkat]
str__linkat:
db "linkat", 0
section .bss.linkat
addr__linkat:
dq 0
section .text.mkdirat exec
global mkdirat
mkdirat:
cmp qword [rel addr__mkdirat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__mkdirat]
lea rdx, [rel addr__mkdirat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__mkdirat]
str__mkdirat:
db "mkdirat", 0
section .bss.mkdirat
addr__mkdirat:
dq 0
section .text.openat exec
global openat
openat:
cmp qword [rel addr__openat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__openat]
lea rdx, [rel addr__openat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__openat]
str__openat:
db "_openat", 0
section .bss.openat
addr__openat:
dq 0
section .text.renameat exec
global renameat
renameat:
cmp qword [rel addr__renameat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__renameat]
lea rdx, [rel addr__renameat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__renameat]
str__renameat:
db "renameat", 0
section .bss.renameat
addr__renameat:
dq 0
section .text.symlinkat exec
global symlinkat
symlinkat:
cmp qword [rel addr__symlinkat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__symlinkat]
lea rdx, [rel addr__symlinkat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__symlinkat]
str__symlinkat:
db "symlinkat", 0
section .bss.symlinkat
addr__symlinkat:
dq 0
section .text.unlinkat exec
global unlinkat
unlinkat:
cmp qword [rel addr__unlinkat], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__unlinkat]
lea rdx, [rel addr__unlinkat]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__unlinkat]
str__unlinkat:
db "unlinkat", 0
section .bss.unlinkat
addr__unlinkat:
dq 0
section .text.pselect exec
global pselect
pselect:
cmp qword [rel addr__pselect], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__pselect]
lea rdx, [rel addr__pselect]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__pselect]
str__pselect:
db "pselect", 0
section .bss.pselect
addr__pselect:
dq 0
section .text.regmgr_call exec
global regmgr_call
regmgr_call:
cmp qword [rel addr__regmgr_call], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__regmgr_call]
lea rdx, [rel addr__regmgr_call]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__regmgr_call]
str__regmgr_call:
db "__sys_regmgr_call", 0
section .bss.regmgr_call
addr__regmgr_call:
dq 0
section .text.dl_get_list exec
global dl_get_list
dl_get_list:
cmp qword [rel addr__dl_get_list], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__dl_get_list]
lea rdx, [rel addr__dl_get_list]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__dl_get_list]
str__dl_get_list:
db "__sys_dl_get_list", 0
section .bss.dl_get_list
addr__dl_get_list:
dq 0
section .text.dl_get_info exec
global dl_get_info
dl_get_info:
cmp qword [rel addr__dl_get_info], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__dl_get_info]
lea rdx, [rel addr__dl_get_info]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__dl_get_info]
str__dl_get_info:
db "__sys_dl_get_info", 0
section .bss.dl_get_info
addr__dl_get_info:
dq 0
section .text.query_memory_protection exec
global query_memory_protection
query_memory_protection:
cmp qword [rel addr__query_memory_protection], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__query_memory_protection]
lea rdx, [rel addr__query_memory_protection]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__query_memory_protection]
str__query_memory_protection:
db "sceKernelQueryMemoryProtection", 0
section .bss.query_memory_protection
addr__query_memory_protection:
dq 0
section .text.batch_map exec
global batch_map
batch_map:
cmp qword [rel addr__batch_map], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__batch_map]
lea rdx, [rel addr__batch_map]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__batch_map]
str__batch_map:
db "sceKernelBatchMap", 0
section .bss.batch_map
addr__batch_map:
dq 0
section .text.osem_open exec
global osem_open
osem_open:
cmp qword [rel addr__osem_open], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__osem_open]
lea rdx, [rel addr__osem_open]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__osem_open]
str__osem_open:
db "__sys_osem_open", 0
section .bss.osem_open
addr__osem_open:
dq 0
section .text.osem_close exec
global osem_close
osem_close:
cmp qword [rel addr__osem_close], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__osem_close]
lea rdx, [rel addr__osem_close]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__osem_close]
str__osem_close:
db "__sys_osem_close", 0
section .bss.osem_close
addr__osem_close:
dq 0
section .text.namedobj_create exec
global namedobj_create
namedobj_create:
cmp qword [rel addr__namedobj_create], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__namedobj_create]
lea rdx, [rel addr__namedobj_create]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__namedobj_create]
str__namedobj_create:
db "__sys_namedobj_create", 0
section .bss.namedobj_create
addr__namedobj_create:
dq 0
section .text.namedobj_delete exec
global namedobj_delete
namedobj_delete:
cmp qword [rel addr__namedobj_delete], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__namedobj_delete]
lea rdx, [rel addr__namedobj_delete]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__namedobj_delete]
str__namedobj_delete:
db "__sys_namedobj_delete", 0
section .bss.namedobj_delete
addr__namedobj_delete:
dq 0
section .text.set_vm_container exec
global set_vm_container
set_vm_container:
cmp qword [rel addr__set_vm_container], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__set_vm_container]
lea rdx, [rel addr__set_vm_container]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__set_vm_container]
str__set_vm_container:
db "sceKernelSetVmContainer", 0
section .bss.set_vm_container
addr__set_vm_container:
dq 0
section .text.debug_init exec
global debug_init
debug_init:
cmp qword [rel addr__debug_init], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__debug_init]
lea rdx, [rel addr__debug_init]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__debug_init]
str__debug_init:
db "__sys_debug_init", 0
section .bss.debug_init
addr__debug_init:
dq 0
section .text.suspend_process exec
global suspend_process
suspend_process:
cmp qword [rel addr__suspend_process], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__suspend_process]
lea rdx, [rel addr__suspend_process]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__suspend_process]
str__suspend_process:
db "__sys_suspend_process", 0
section .bss.suspend_process
addr__suspend_process:
dq 0
section .text.resume_process exec
global resume_process
resume_process:
cmp qword [rel addr__resume_process], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__resume_process]
lea rdx, [rel addr__resume_process]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__resume_process]
str__resume_process:
db "__sys_resume_process", 0
section .bss.resume_process
addr__resume_process:
dq 0
section .text.opmc_enable exec
global opmc_enable
opmc_enable:
cmp qword [rel addr__opmc_enable], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__opmc_enable]
lea rdx, [rel addr__opmc_enable]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__opmc_enable]
str__opmc_enable:
db "__sys_opmc_enable", 0
section .bss.opmc_enable
addr__opmc_enable:
dq 0
section .text.opmc_disable exec
global opmc_disable
opmc_disable:
cmp qword [rel addr__opmc_disable], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__opmc_disable]
lea rdx, [rel addr__opmc_disable]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__opmc_disable]
str__opmc_disable:
db "__sys_opmc_disable", 0
section .bss.opmc_disable
addr__opmc_disable:
dq 0
section .text.opmc_set_ctl exec
global opmc_set_ctl
opmc_set_ctl:
cmp qword [rel addr__opmc_set_ctl], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__opmc_set_ctl]
lea rdx, [rel addr__opmc_set_ctl]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__opmc_set_ctl]
str__opmc_set_ctl:
db "__sys_opmc_set_ctl", 0
section .bss.opmc_set_ctl
addr__opmc_set_ctl:
dq 0
section .text.opmc_set_ctr exec
global opmc_set_ctr
opmc_set_ctr:
cmp qword [rel addr__opmc_set_ctr], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__opmc_set_ctr]
lea rdx, [rel addr__opmc_set_ctr]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__opmc_set_ctr]
str__opmc_set_ctr:
db "__sys_opmc_set_ctr", 0
section .bss.opmc_set_ctr
addr__opmc_set_ctr:
dq 0
section .text.opmc_get_ctr exec
global opmc_get_ctr
opmc_get_ctr:
cmp qword [rel addr__opmc_get_ctr], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__opmc_get_ctr]
lea rdx, [rel addr__opmc_get_ctr]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__opmc_get_ctr]
str__opmc_get_ctr:
db "__sys_opmc_get_ctr", 0
section .bss.opmc_get_ctr
addr__opmc_get_ctr:
dq 0
section .text.virtual_query exec
global virtual_query
virtual_query:
cmp qword [rel addr__virtual_query], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__virtual_query]
lea rdx, [rel addr__virtual_query]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__virtual_query]
str__virtual_query:
db "sceKernelVirtualQuery", 0
section .bss.virtual_query
addr__virtual_query:
dq 0
section .text.mdbg_call exec
global mdbg_call
mdbg_call:
cmp qword [rel addr__mdbg_call], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__mdbg_call]
lea rdx, [rel addr__mdbg_call]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__mdbg_call]
str__mdbg_call:
db "mdbg_call", 0
section .bss.mdbg_call
addr__mdbg_call:
dq 0
section .text.is_in_sandbox exec
global is_in_sandbox
is_in_sandbox:
cmp qword [rel addr__is_in_sandbox], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__is_in_sandbox]
lea rdx, [rel addr__is_in_sandbox]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__is_in_sandbox]
str__is_in_sandbox:
db "is_in_sandbox", 0
section .bss.is_in_sandbox
addr__is_in_sandbox:
dq 0
section .text.get_authinfo exec
global get_authinfo
get_authinfo:
cmp qword [rel addr__get_authinfo], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_authinfo]
lea rdx, [rel addr__get_authinfo]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_authinfo]
str__get_authinfo:
db "get_authinfo", 0
section .bss.get_authinfo
addr__get_authinfo:
dq 0
section .text.dynlib_dlsym exec
global dynlib_dlsym
dynlib_dlsym:
cmp qword [rel addr__dynlib_dlsym], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__dynlib_dlsym]
lea rdx, [rel addr__dynlib_dlsym]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__dynlib_dlsym]
str__dynlib_dlsym:
db "sceKernelDlsym", 0
section .bss.dynlib_dlsym
addr__dynlib_dlsym:
dq 0
section .text.dynlib_load_prx exec
global dynlib_load_prx
dynlib_load_prx:
cmp qword [rel addr__dynlib_load_prx], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__dynlib_load_prx]
lea rdx, [rel addr__dynlib_load_prx]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__dynlib_load_prx]
str__dynlib_load_prx:
db "__sys_dynlib_load_prx", 0
section .bss.dynlib_load_prx
addr__dynlib_load_prx:
dq 0
section .text.sandbox_path exec
global sandbox_path
sandbox_path:
cmp qword [rel addr__sandbox_path], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sandbox_path]
lea rdx, [rel addr__sandbox_path]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sandbox_path]
str__sandbox_path:
db "sceKernelSandboxPath", 0
section .bss.sandbox_path
addr__sandbox_path:
dq 0
section .text.mdbg_service exec
global mdbg_service
mdbg_service:
cmp qword [rel addr__mdbg_service], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__mdbg_service]
lea rdx, [rel addr__mdbg_service]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__mdbg_service]
str__mdbg_service:
db "mdbg_service", 0
section .bss.mdbg_service
addr__mdbg_service:
dq 0
section .text.randomized_path exec
global randomized_path
randomized_path:
cmp qword [rel addr__randomized_path], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__randomized_path]
lea rdx, [rel addr__randomized_path]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__randomized_path]
str__randomized_path:
db "__sys_randomized_path", 0
section .bss.randomized_path
addr__randomized_path:
dq 0
section .text.rdup exec
global rdup
rdup:
cmp qword [rel addr__rdup], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__rdup]
lea rdx, [rel addr__rdup]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__rdup]
str__rdup:
db "__sys_rdup", 0
section .bss.rdup
addr__rdup:
dq 0
section .text.dl_get_metadata exec
global dl_get_metadata
dl_get_metadata:
cmp qword [rel addr__dl_get_metadata], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__dl_get_metadata]
lea rdx, [rel addr__dl_get_metadata]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__dl_get_metadata]
str__dl_get_metadata:
db "__sys_dl_get_metadata", 0
section .bss.dl_get_metadata
addr__dl_get_metadata:
dq 0
section .text.workaround8849 exec
global workaround8849
workaround8849:
cmp qword [rel addr__workaround8849], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__workaround8849]
lea rdx, [rel addr__workaround8849]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__workaround8849]
str__workaround8849:
db "__sys_workaround8849", 0
section .bss.workaround8849
addr__workaround8849:
dq 0
section .text.is_development_mode exec
global is_development_mode
is_development_mode:
cmp qword [rel addr__is_development_mode], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__is_development_mode]
lea rdx, [rel addr__is_development_mode]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__is_development_mode]
str__is_development_mode:
db "__sys_is_development_mode", 0
section .bss.is_development_mode
addr__is_development_mode:
dq 0
section .text.get_self_auth_info exec
global get_self_auth_info
get_self_auth_info:
cmp qword [rel addr__get_self_auth_info], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_self_auth_info]
lea rdx, [rel addr__get_self_auth_info]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_self_auth_info]
str__get_self_auth_info:
db "get_self_auth_info", 0
section .bss.get_self_auth_info
addr__get_self_auth_info:
dq 0
section .text.get_paging_stats_of_all_threads exec
global get_paging_stats_of_all_threads
get_paging_stats_of_all_threads:
cmp qword [rel addr__get_paging_stats_of_all_threads], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_paging_stats_of_all_threads]
lea rdx, [rel addr__get_paging_stats_of_all_threads]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_paging_stats_of_all_threads]
str__get_paging_stats_of_all_threads:
db "sceKernelGetPagingStatsOfAllThreads", 0
section .bss.get_paging_stats_of_all_threads
addr__get_paging_stats_of_all_threads:
dq 0
section .text.get_proc_type_info exec
global get_proc_type_info
get_proc_type_info:
cmp qword [rel addr__get_proc_type_info], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_proc_type_info]
lea rdx, [rel addr__get_proc_type_info]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_proc_type_info]
str__get_proc_type_info:
db "__sys_get_proc_type_info", 0
section .bss.get_proc_type_info
addr__get_proc_type_info:
dq 0
section .text.get_resident_count exec
global get_resident_count
get_resident_count:
cmp qword [rel addr__get_resident_count], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_resident_count]
lea rdx, [rel addr__get_resident_count]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_resident_count]
str__get_resident_count:
db "sceKernelGetResidentCount", 0
section .bss.get_resident_count
addr__get_resident_count:
dq 0
section .text.prepare_to_suspend_process exec
global prepare_to_suspend_process
prepare_to_suspend_process:
cmp qword [rel addr__prepare_to_suspend_process], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__prepare_to_suspend_process]
lea rdx, [rel addr__prepare_to_suspend_process]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__prepare_to_suspend_process]
str__prepare_to_suspend_process:
db "sceKernelPrepareToSuspendProcess", 0
section .bss.prepare_to_suspend_process
addr__prepare_to_suspend_process:
dq 0
section .text.get_resident_fmem_count exec
global get_resident_fmem_count
get_resident_fmem_count:
cmp qword [rel addr__get_resident_fmem_count], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_resident_fmem_count]
lea rdx, [rel addr__get_resident_fmem_count]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_resident_fmem_count]
str__get_resident_fmem_count:
db "sceKernelGetResidentFmemCount", 0
section .bss.get_resident_fmem_count
addr__get_resident_fmem_count:
dq 0
section .text.get_paging_stats_of_all_objects exec
global get_paging_stats_of_all_objects
get_paging_stats_of_all_objects:
cmp qword [rel addr__get_paging_stats_of_all_objects], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_paging_stats_of_all_objects]
lea rdx, [rel addr__get_paging_stats_of_all_objects]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_paging_stats_of_all_objects]
str__get_paging_stats_of_all_objects:
db "sceKernelGetPagingStatsOfAllObjects", 0
section .bss.get_paging_stats_of_all_objects
addr__get_paging_stats_of_all_objects:
dq 0
section .text.test_debug_rwmem exec
global test_debug_rwmem
test_debug_rwmem:
cmp qword [rel addr__test_debug_rwmem], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__test_debug_rwmem]
lea rdx, [rel addr__test_debug_rwmem]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__test_debug_rwmem]
str__test_debug_rwmem:
db "__sys_test_debug_rwmem", 0
section .bss.test_debug_rwmem
addr__test_debug_rwmem:
dq 0
section .text.suspend_system exec
global suspend_system
suspend_system:
cmp qword [rel addr__suspend_system], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__suspend_system]
lea rdx, [rel addr__suspend_system]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__suspend_system]
str__suspend_system:
db "sceKernelSuspendSystem", 0
section .bss.suspend_system
addr__suspend_system:
dq 0
section .text.ipmimgr_call exec
global ipmimgr_call
ipmimgr_call:
cmp qword [rel addr__ipmimgr_call], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__ipmimgr_call]
lea rdx, [rel addr__ipmimgr_call]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__ipmimgr_call]
str__ipmimgr_call:
db "ipmimgr_call", 0
section .bss.ipmimgr_call
addr__ipmimgr_call:
dq 0
section .text.get_vm_map_timestamp exec
global get_vm_map_timestamp
get_vm_map_timestamp:
cmp qword [rel addr__get_vm_map_timestamp], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_vm_map_timestamp]
lea rdx, [rel addr__get_vm_map_timestamp]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_vm_map_timestamp]
str__get_vm_map_timestamp:
db "get_vm_map_timestamp", 0
section .bss.get_vm_map_timestamp
addr__get_vm_map_timestamp:
dq 0
section .text.opmc_set_hw exec
global opmc_set_hw
opmc_set_hw:
cmp qword [rel addr__opmc_set_hw], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__opmc_set_hw]
lea rdx, [rel addr__opmc_set_hw]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__opmc_set_hw]
str__opmc_set_hw:
db "__sys_opmc_set_hw", 0
section .bss.opmc_set_hw
addr__opmc_set_hw:
dq 0
section .text.opmc_get_hw exec
global opmc_get_hw
opmc_get_hw:
cmp qword [rel addr__opmc_get_hw], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__opmc_get_hw]
lea rdx, [rel addr__opmc_get_hw]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__opmc_get_hw]
str__opmc_get_hw:
db "__sys_opmc_get_hw", 0
section .bss.opmc_get_hw
addr__opmc_get_hw:
dq 0
section .text.get_cpu_usage_all exec
global get_cpu_usage_all
get_cpu_usage_all:
cmp qword [rel addr__get_cpu_usage_all], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_cpu_usage_all]
lea rdx, [rel addr__get_cpu_usage_all]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_cpu_usage_all]
str__get_cpu_usage_all:
db "sceKernelGetCpuUsageAll", 0
section .bss.get_cpu_usage_all
addr__get_cpu_usage_all:
dq 0
section .text.physhm_open exec
global physhm_open
physhm_open:
cmp qword [rel addr__physhm_open], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__physhm_open]
lea rdx, [rel addr__physhm_open]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__physhm_open]
str__physhm_open:
db "physhm_open", 0
section .bss.physhm_open
addr__physhm_open:
dq 0
section .text.physhm_unlink exec
global physhm_unlink
physhm_unlink:
cmp qword [rel addr__physhm_unlink], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__physhm_unlink]
lea rdx, [rel addr__physhm_unlink]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__physhm_unlink]
str__physhm_unlink:
db "physhm_unlink", 0
section .bss.physhm_unlink
addr__physhm_unlink:
dq 0
section .text.resume_internal_hdd exec
global resume_internal_hdd
resume_internal_hdd:
cmp qword [rel addr__resume_internal_hdd], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__resume_internal_hdd]
lea rdx, [rel addr__resume_internal_hdd]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__resume_internal_hdd]
str__resume_internal_hdd:
db "__sys_resume_internal_hdd", 0
section .bss.resume_internal_hdd
addr__resume_internal_hdd:
dq 0
section .text.set_timezone_info exec
global set_timezone_info
set_timezone_info:
cmp qword [rel addr__set_timezone_info], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__set_timezone_info]
lea rdx, [rel addr__set_timezone_info]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__set_timezone_info]
str__set_timezone_info:
db "sceKernelSetTimezoneInfo", 0
section .bss.set_timezone_info
addr__set_timezone_info:
dq 0
section .text.set_phys_fmem_limit exec
global set_phys_fmem_limit
set_phys_fmem_limit:
cmp qword [rel addr__set_phys_fmem_limit], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__set_phys_fmem_limit]
lea rdx, [rel addr__set_phys_fmem_limit]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__set_phys_fmem_limit]
str__set_phys_fmem_limit:
db "set_phys_fmem_limit", 0
section .bss.set_phys_fmem_limit
addr__set_phys_fmem_limit:
dq 0
section .text.set_uevt exec
global set_uevt
set_uevt:
cmp qword [rel addr__set_uevt], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__set_uevt]
lea rdx, [rel addr__set_uevt]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__set_uevt]
str__set_uevt:
db "__sys_set_uevt", 0
section .bss.set_uevt
addr__set_uevt:
dq 0
section .text.get_cpu_usage_proc exec
global get_cpu_usage_proc
get_cpu_usage_proc:
cmp qword [rel addr__get_cpu_usage_proc], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_cpu_usage_proc]
lea rdx, [rel addr__get_cpu_usage_proc]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_cpu_usage_proc]
str__get_cpu_usage_proc:
db "sceKernelGetCpuUsageProc", 0
section .bss.get_cpu_usage_proc
addr__get_cpu_usage_proc:
dq 0
section .text.get_sdk_compiled_version exec
global get_sdk_compiled_version
get_sdk_compiled_version:
cmp qword [rel addr__get_sdk_compiled_version], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_sdk_compiled_version]
lea rdx, [rel addr__get_sdk_compiled_version]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_sdk_compiled_version]
str__get_sdk_compiled_version:
db "get_sdk_compiled_version", 0
section .bss.get_sdk_compiled_version
addr__get_sdk_compiled_version:
dq 0
section .text.dynlib_get_obj_member exec
global dynlib_get_obj_member
dynlib_get_obj_member:
cmp qword [rel addr__dynlib_get_obj_member], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__dynlib_get_obj_member]
lea rdx, [rel addr__dynlib_get_obj_member]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__dynlib_get_obj_member]
str__dynlib_get_obj_member:
db "dynlib_get_obj_member", 0
section .bss.dynlib_get_obj_member
addr__dynlib_get_obj_member:
dq 0
section .text.prepare_to_resume_process exec
global prepare_to_resume_process
prepare_to_resume_process:
cmp qword [rel addr__prepare_to_resume_process], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__prepare_to_resume_process]
lea rdx, [rel addr__prepare_to_resume_process]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__prepare_to_resume_process]
str__prepare_to_resume_process:
db "sceKernelPrepareToResumeProcess", 0
section .bss.prepare_to_resume_process
addr__prepare_to_resume_process:
dq 0
section .text.blockpool_open exec
global blockpool_open
blockpool_open:
cmp qword [rel addr__blockpool_open], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__blockpool_open]
lea rdx, [rel addr__blockpool_open]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__blockpool_open]
str__blockpool_open:
db "blockpool_open", 0
section .bss.blockpool_open
addr__blockpool_open:
dq 0
section .text.blockpool_map exec
global blockpool_map
blockpool_map:
cmp qword [rel addr__blockpool_map], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__blockpool_map]
lea rdx, [rel addr__blockpool_map]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__blockpool_map]
str__blockpool_map:
db "blockpool_map", 0
section .bss.blockpool_map
addr__blockpool_map:
dq 0
section .text.blockpool_unmap exec
global blockpool_unmap
blockpool_unmap:
cmp qword [rel addr__blockpool_unmap], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__blockpool_unmap]
lea rdx, [rel addr__blockpool_unmap]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__blockpool_unmap]
str__blockpool_unmap:
db "blockpool_unmap", 0
section .bss.blockpool_unmap
addr__blockpool_unmap:
dq 0
section .text.dynlib_get_info_for_libdbg exec
global dynlib_get_info_for_libdbg
dynlib_get_info_for_libdbg:
cmp qword [rel addr__dynlib_get_info_for_libdbg], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__dynlib_get_info_for_libdbg]
lea rdx, [rel addr__dynlib_get_info_for_libdbg]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__dynlib_get_info_for_libdbg]
str__dynlib_get_info_for_libdbg:
db "__sys_dynlib_get_info_for_libdbg", 0
section .bss.dynlib_get_info_for_libdbg
addr__dynlib_get_info_for_libdbg:
dq 0
section .text.blockpool_batch exec
global blockpool_batch
blockpool_batch:
cmp qword [rel addr__blockpool_batch], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__blockpool_batch]
lea rdx, [rel addr__blockpool_batch]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__blockpool_batch]
str__blockpool_batch:
db "blockpool_batch", 0
section .bss.blockpool_batch
addr__blockpool_batch:
dq 0
section .text.fdatasync exec
global fdatasync
fdatasync:
cmp qword [rel addr__fdatasync], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__fdatasync]
lea rdx, [rel addr__fdatasync]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__fdatasync]
str__fdatasync:
db "fdatasync", 0
section .bss.fdatasync
addr__fdatasync:
dq 0
section .text.dynlib_get_list2 exec
global dynlib_get_list2
dynlib_get_list2:
cmp qword [rel addr__dynlib_get_list2], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__dynlib_get_list2]
lea rdx, [rel addr__dynlib_get_list2]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__dynlib_get_list2]
str__dynlib_get_list2:
db "__sys_dynlib_get_list2", 0
section .bss.dynlib_get_list2
addr__dynlib_get_list2:
dq 0
section .text.dynlib_get_info2 exec
global dynlib_get_info2
dynlib_get_info2:
cmp qword [rel addr__dynlib_get_info2], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__dynlib_get_info2]
lea rdx, [rel addr__dynlib_get_info2]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__dynlib_get_info2]
str__dynlib_get_info2:
db "__sys_dynlib_get_info2", 0
section .bss.dynlib_get_info2
addr__dynlib_get_info2:
dq 0
section .text.get_bio_usage_all exec
global get_bio_usage_all
get_bio_usage_all:
cmp qword [rel addr__get_bio_usage_all], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_bio_usage_all]
lea rdx, [rel addr__get_bio_usage_all]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_bio_usage_all]
str__get_bio_usage_all:
db "sceKernelGetBioUsageAll", 0
section .bss.get_bio_usage_all
addr__get_bio_usage_all:
dq 0
section .text.get_page_table_stats exec
global get_page_table_stats
get_page_table_stats:
cmp qword [rel addr__get_page_table_stats], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_page_table_stats]
lea rdx, [rel addr__get_page_table_stats]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_page_table_stats]
str__get_page_table_stats:
db "get_page_table_stats", 0
section .bss.get_page_table_stats
addr__get_page_table_stats:
dq 0
section .text.dynlib_get_list_for_libdbg exec
global dynlib_get_list_for_libdbg
dynlib_get_list_for_libdbg:
cmp qword [rel addr__dynlib_get_list_for_libdbg], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__dynlib_get_list_for_libdbg]
lea rdx, [rel addr__dynlib_get_list_for_libdbg]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__dynlib_get_list_for_libdbg]
str__dynlib_get_list_for_libdbg:
db "__sys_dynlib_get_list_for_libdbg", 0
section .bss.dynlib_get_list_for_libdbg
addr__dynlib_get_list_for_libdbg:
dq 0
section .text.virtual_query_all exec
global virtual_query_all
virtual_query_all:
cmp qword [rel addr__virtual_query_all], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__virtual_query_all]
lea rdx, [rel addr__virtual_query_all]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__virtual_query_all]
str__virtual_query_all:
db "sceKernelVirtualQueryAll", 0
section .bss.virtual_query_all
addr__virtual_query_all:
dq 0
section .text.reserve_2mb_page exec
global reserve_2mb_page
reserve_2mb_page:
cmp qword [rel addr__reserve_2mb_page], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__reserve_2mb_page]
lea rdx, [rel addr__reserve_2mb_page]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__reserve_2mb_page]
str__reserve_2mb_page:
db "sceKernelReserve2mbPage", 0
section .bss.reserve_2mb_page
addr__reserve_2mb_page:
dq 0
section .text.get_phys_page_size exec
global get_phys_page_size
get_phys_page_size:
cmp qword [rel addr__get_phys_page_size], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__get_phys_page_size]
lea rdx, [rel addr__get_phys_page_size]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__get_phys_page_size]
str__get_phys_page_size:
db "sceKernelGetPhysPageSize", 0
section .bss.get_phys_page_size
addr__get_phys_page_size:
dq 0
section .text.pthread_create exec
global pthread_create
pthread_create:
cmp qword [rel addr__pthread_create], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__pthread_create]
lea rdx, [rel addr__pthread_create]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__pthread_create]
str__pthread_create:
db "pthread_create", 0
section .bss.pthread_create
addr__pthread_create:
dq 0
section .text.pthread_exit exec
global pthread_exit
pthread_exit:
cmp qword [rel addr__pthread_exit], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__pthread_exit]
lea rdx, [rel addr__pthread_exit]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__pthread_exit]
str__pthread_exit:
db "pthread_exit", 0
section .bss.pthread_exit
addr__pthread_exit:
dq 0
section .text.pthread_kill exec
global pthread_kill
pthread_kill:
cmp qword [rel addr__pthread_kill], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__pthread_kill]
lea rdx, [rel addr__pthread_kill]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__pthread_kill]
str__pthread_kill:
db "pthread_kill", 0
section .bss.pthread_kill
addr__pthread_kill:
dq 0
section .text.sceKernelLoadStartModule exec
global sceKernelLoadStartModule
sceKernelLoadStartModule:
cmp qword [rel addr__sceKernelLoadStartModule], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__sceKernelLoadStartModule]
lea rdx, [rel addr__sceKernelLoadStartModule]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__sceKernelLoadStartModule]
str__sceKernelLoadStartModule:
db "sceKernelLoadStartModule", 0
section .bss.sceKernelLoadStartModule
addr__sceKernelLoadStartModule:
dq 0
section .text.__error exec
global __error
__error:
cmp qword [rel addr____error], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str____error]
lea rdx, [rel addr____error]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr____error]
str____error:
db "__error", 0
section .bss.__error
addr____error:
dq 0
section .text.pthread_detach exec
global pthread_detach
pthread_detach:
cmp qword [rel addr__pthread_detach], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__pthread_detach]
lea rdx, [rel addr__pthread_detach]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__pthread_detach]
str__pthread_detach:
db "pthread_detach", 0
section .bss.pthread_detach
addr__pthread_detach:
dq 0
section .text.rfork_thread exec
global rfork_thread
rfork_thread:
cmp qword [rel addr__rfork_thread], 0
jne .resolved
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
mov edi, 0x1
lea rsi, [rel str__rfork_thread]
lea rdx, [rel addr__rfork_thread]
call [rel addr__dynlib_dlsym]
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
.resolved:
jmp [rel addr__rfork_thread]
str__rfork_thread:
db "rfork_thread", 0
section .bss.rfork_thread
addr__rfork_thread:
dq 0
