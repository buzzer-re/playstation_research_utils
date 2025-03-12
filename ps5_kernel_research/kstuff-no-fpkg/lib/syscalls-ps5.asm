section .text
use64
global p_syscall

section .text.nosys exec
global nosys
nosys:
mov eax, 0
jmp common_syscall
section .text.sys_exit exec
global sys_exit
sys_exit:
mov eax, 1
jmp common_syscall
section .text.fork exec
global fork
fork:
mov eax, 2
jmp common_syscall
section .text.read exec
global read
read:
mov eax, 3
jmp common_syscall
section .text.write exec
global write
write:
mov eax, 4
jmp common_syscall
section .text.open exec
global open
open:
mov eax, 5
jmp common_syscall
section .text.close exec
global close
close:
mov eax, 6
jmp common_syscall
section .text.wait4 exec
global wait4
wait4:
mov eax, 7
jmp common_syscall
section .text.link exec
global link
link:
mov eax, 9
jmp common_syscall
section .text.unlink exec
global unlink
unlink:
mov eax, 10
jmp common_syscall
section .text.chdir exec
global chdir
chdir:
mov eax, 12
jmp common_syscall
section .text.fchdir exec
global fchdir
fchdir:
mov eax, 13
jmp common_syscall
section .text.mknod exec
global mknod
mknod:
mov eax, 14
jmp common_syscall
section .text.chmod exec
global chmod
chmod:
mov eax, 15
jmp common_syscall
section .text.chown exec
global chown
chown:
mov eax, 16
jmp common_syscall
section .text.obreak exec
global obreak
obreak:
mov eax, 17
jmp common_syscall
section .text.getpid exec
global getpid
getpid:
mov eax, 20
jmp common_syscall
section .text.mount exec
global mount
mount:
mov eax, 21
jmp common_syscall
section .text.unmount exec
global unmount
unmount:
mov eax, 22
jmp common_syscall
section .text.setuid exec
global setuid
setuid:
mov eax, 23
jmp common_syscall
section .text.getuid exec
global getuid
getuid:
mov eax, 24
jmp common_syscall
section .text.geteuid exec
global geteuid
geteuid:
mov eax, 25
jmp common_syscall
section .text.ptrace exec
global ptrace
ptrace:
mov eax, 26
jmp common_syscall
section .text.recvmsg exec
global recvmsg
recvmsg:
mov eax, 27
jmp common_syscall
section .text.sendmsg exec
global sendmsg
sendmsg:
mov eax, 28
jmp common_syscall
section .text.recvfrom exec
global recvfrom
recvfrom:
mov eax, 29
jmp common_syscall
section .text.accept exec
global accept
accept:
mov eax, 30
jmp common_syscall
section .text.getpeername exec
global getpeername
getpeername:
mov eax, 31
jmp common_syscall
section .text.getsockname exec
global getsockname
getsockname:
mov eax, 32
jmp common_syscall
section .text.access exec
global access
access:
mov eax, 33
jmp common_syscall
section .text.chflags exec
global chflags
chflags:
mov eax, 34
jmp common_syscall
section .text.fchflags exec
global fchflags
fchflags:
mov eax, 35
jmp common_syscall
section .text.sync exec
global sync
sync:
mov eax, 36
jmp common_syscall
section .text.kill exec
global kill
kill:
mov eax, 37
jmp common_syscall
section .text.getppid exec
global getppid
getppid:
mov eax, 39
jmp common_syscall
section .text.dup exec
global dup
dup:
mov eax, 41
jmp common_syscall
section .text.pipe exec
global pipe
pipe:
mov eax, 42
push rbp
call common_syscall
pop rbp
cmp eax, -1
jz .skip_write
mov [rdi], eax
mov [rdi+4], edx
xor eax, eax
.skip_write:
ret
section .text.getegid exec
global getegid
getegid:
mov eax, 43
jmp common_syscall
section .text.profil exec
global profil
profil:
mov eax, 44
jmp common_syscall
section .text.ktrace exec
global ktrace
ktrace:
mov eax, 45
jmp common_syscall
section .text.getgid exec
global getgid
getgid:
mov eax, 47
jmp common_syscall
section .text.getlogin exec
global getlogin
getlogin:
mov eax, 49
jmp common_syscall
section .text.setlogin exec
global setlogin
setlogin:
mov eax, 50
jmp common_syscall
section .text.acct exec
global acct
acct:
mov eax, 51
jmp common_syscall
section .text.sigaltstack exec
global sigaltstack
sigaltstack:
mov eax, 53
jmp common_syscall
section .text.ioctl exec
global ioctl
ioctl:
mov eax, 54
jmp common_syscall
section .text.reboot exec
global reboot
reboot:
mov eax, 55
jmp common_syscall
section .text.revoke exec
global revoke
revoke:
mov eax, 56
jmp common_syscall
section .text.symlink exec
global symlink
symlink:
mov eax, 57
jmp common_syscall
section .text.readlink exec
global readlink
readlink:
mov eax, 58
jmp common_syscall
section .text.execve exec
global execve
execve:
mov eax, 59
jmp common_syscall
section .text.umask exec
global umask
umask:
mov eax, 60
jmp common_syscall
section .text.chroot exec
global chroot
chroot:
mov eax, 61
jmp common_syscall
section .text.msync exec
global msync
msync:
mov eax, 65
jmp common_syscall
section .text.vfork exec
global vfork
vfork:
mov eax, 66
jmp common_syscall
section .text.sbrk exec
global sbrk
sbrk:
mov eax, 69
jmp common_syscall
section .text.sstk exec
global sstk
sstk:
mov eax, 70
jmp common_syscall
section .text.ovadvise exec
global ovadvise
ovadvise:
mov eax, 72
jmp common_syscall
section .text.munmap exec
global munmap
munmap:
mov eax, 73
jmp common_syscall
section .text.mprotect exec
global mprotect
mprotect:
mov eax, 74
jmp common_syscall
section .text.madvise exec
global madvise
madvise:
mov eax, 75
jmp common_syscall
section .text.mincore exec
global mincore
mincore:
mov eax, 78
jmp common_syscall
section .text.getgroups exec
global getgroups
getgroups:
mov eax, 79
jmp common_syscall
section .text.setgroups exec
global setgroups
setgroups:
mov eax, 80
jmp common_syscall
section .text.getpgrp exec
global getpgrp
getpgrp:
mov eax, 81
jmp common_syscall
section .text.setpgid exec
global setpgid
setpgid:
mov eax, 82
jmp common_syscall
section .text.setitimer exec
global setitimer
setitimer:
mov eax, 83
jmp common_syscall
section .text.swapon exec
global swapon
swapon:
mov eax, 85
jmp common_syscall
section .text.getitimer exec
global getitimer
getitimer:
mov eax, 86
jmp common_syscall
section .text.getdtablesize exec
global getdtablesize
getdtablesize:
mov eax, 89
jmp common_syscall
section .text.dup2 exec
global dup2
dup2:
mov eax, 90
jmp common_syscall
section .text.fcntl exec
global fcntl
fcntl:
mov eax, 92
jmp common_syscall
section .text.select exec
global select
select:
mov eax, 93
jmp common_syscall
section .text.fsync exec
global fsync
fsync:
mov eax, 95
jmp common_syscall
section .text.setpriority exec
global setpriority
setpriority:
mov eax, 96
jmp common_syscall
section .text.socket exec
global socket
socket:
mov eax, 97
jmp common_syscall
section .text.connect exec
global connect
connect:
mov eax, 98
jmp common_syscall
section .text.netcontrol exec
global netcontrol
netcontrol:
mov eax, 99
jmp common_syscall
section .text.getpriority exec
global getpriority
getpriority:
mov eax, 100
jmp common_syscall
section .text.netabort exec
global netabort
netabort:
mov eax, 101
jmp common_syscall
section .text.netgetsockinfo exec
global netgetsockinfo
netgetsockinfo:
mov eax, 102
jmp common_syscall
section .text.bind exec
global bind
bind:
mov eax, 104
jmp common_syscall
section .text.setsockopt exec
global setsockopt
setsockopt:
mov eax, 105
jmp common_syscall
section .text.listen exec
global listen
listen:
mov eax, 106
jmp common_syscall
section .text.socketex exec
global socketex
socketex:
mov eax, 113
jmp common_syscall
section .text.socketclose exec
global socketclose
socketclose:
mov eax, 114
jmp common_syscall
section .text.gettimeofday exec
global gettimeofday
gettimeofday:
mov eax, 116
jmp common_syscall
section .text.getrusage exec
global getrusage
getrusage:
mov eax, 117
jmp common_syscall
section .text.getsockopt exec
global getsockopt
getsockopt:
mov eax, 118
jmp common_syscall
section .text.readv exec
global readv
readv:
mov eax, 120
jmp common_syscall
section .text.writev exec
global writev
writev:
mov eax, 121
jmp common_syscall
section .text.settimeofday exec
global settimeofday
settimeofday:
mov eax, 122
jmp common_syscall
section .text.fchown exec
global fchown
fchown:
mov eax, 123
jmp common_syscall
section .text.fchmod exec
global fchmod
fchmod:
mov eax, 124
jmp common_syscall
section .text.netgetiflist exec
global netgetiflist
netgetiflist:
mov eax, 125
jmp common_syscall
section .text.setreuid exec
global setreuid
setreuid:
mov eax, 126
jmp common_syscall
section .text.setregid exec
global setregid
setregid:
mov eax, 127
jmp common_syscall
section .text.rename exec
global rename
rename:
mov eax, 128
jmp common_syscall
section .text.flock exec
global flock
flock:
mov eax, 131
jmp common_syscall
section .text.mkfifo exec
global mkfifo
mkfifo:
mov eax, 132
jmp common_syscall
section .text.sendto exec
global sendto
sendto:
mov eax, 133
jmp common_syscall
section .text.shutdown exec
global shutdown
shutdown:
mov eax, 134
jmp common_syscall
section .text.socketpair exec
global socketpair
socketpair:
mov eax, 135
jmp common_syscall
section .text.mkdir exec
global mkdir
mkdir:
mov eax, 136
jmp common_syscall
section .text.rmdir exec
global rmdir
rmdir:
mov eax, 137
jmp common_syscall
section .text.utimes exec
global utimes
utimes:
mov eax, 138
jmp common_syscall
section .text.adjtime exec
global adjtime
adjtime:
mov eax, 140
jmp common_syscall
section .text.kqueueex exec
global kqueueex
kqueueex:
mov eax, 141
jmp common_syscall
section .text.setsid exec
global setsid
setsid:
mov eax, 147
jmp common_syscall
section .text.quotactl exec
global quotactl
quotactl:
mov eax, 148
jmp common_syscall
section .text.lgetfh exec
global lgetfh
lgetfh:
mov eax, 160
jmp common_syscall
section .text.getfh exec
global getfh
getfh:
mov eax, 161
jmp common_syscall
section .text.sysarch exec
global sysarch
sysarch:
mov eax, 165
jmp common_syscall
section .text.rtprio exec
global rtprio
rtprio:
mov eax, 166
jmp common_syscall
section .text.freebsd6_pread exec
global freebsd6_pread
freebsd6_pread:
mov eax, 173
jmp common_syscall
section .text.freebsd6_pwrite exec
global freebsd6_pwrite
freebsd6_pwrite:
mov eax, 174
jmp common_syscall
section .text.setfib exec
global setfib
setfib:
mov eax, 175
jmp common_syscall
section .text.ntp_adjtime exec
global ntp_adjtime
ntp_adjtime:
mov eax, 176
jmp common_syscall
section .text.setgid exec
global setgid
setgid:
mov eax, 181
jmp common_syscall
section .text.setegid exec
global setegid
setegid:
mov eax, 182
jmp common_syscall
section .text.seteuid exec
global seteuid
seteuid:
mov eax, 183
jmp common_syscall
section .text.stat exec
global stat
stat:
mov eax, 188
jmp common_syscall
section .text.fstat exec
global fstat
fstat:
mov eax, 189
jmp common_syscall
section .text.lstat exec
global lstat
lstat:
mov eax, 190
jmp common_syscall
section .text.pathconf exec
global pathconf
pathconf:
mov eax, 191
jmp common_syscall
section .text.fpathconf exec
global fpathconf
fpathconf:
mov eax, 192
jmp common_syscall
section .text.getrlimit exec
global getrlimit
getrlimit:
mov eax, 194
jmp common_syscall
section .text.setrlimit exec
global setrlimit
setrlimit:
mov eax, 195
jmp common_syscall
section .text.getdirentries exec
global getdirentries
getdirentries:
mov eax, 196
jmp common_syscall
section .text.freebsd6_mmap exec
global freebsd6_mmap
freebsd6_mmap:
mov eax, 197
jmp common_syscall
section .text.freebsd6_lseek exec
global freebsd6_lseek
freebsd6_lseek:
mov eax, 199
jmp common_syscall
section .text.freebsd6_truncate exec
global freebsd6_truncate
freebsd6_truncate:
mov eax, 200
jmp common_syscall
section .text.freebsd6_ftruncate exec
global freebsd6_ftruncate
freebsd6_ftruncate:
mov eax, 201
jmp common_syscall
section .text.__sysctl exec
global __sysctl
__sysctl:
mov eax, 202
jmp common_syscall
section .text.mlock exec
global mlock
mlock:
mov eax, 203
jmp common_syscall
section .text.munlock exec
global munlock
munlock:
mov eax, 204
jmp common_syscall
section .text.undelete exec
global undelete
undelete:
mov eax, 205
jmp common_syscall
section .text.futimes exec
global futimes
futimes:
mov eax, 206
jmp common_syscall
section .text.getpgid exec
global getpgid
getpgid:
mov eax, 207
jmp common_syscall
section .text.poll exec
global poll
poll:
mov eax, 209
jmp common_syscall
section .text.clock_gettime exec
global clock_gettime
clock_gettime:
mov eax, 232
jmp common_syscall
section .text.clock_settime exec
global clock_settime
clock_settime:
mov eax, 233
jmp common_syscall
section .text.clock_getres exec
global clock_getres
clock_getres:
mov eax, 234
jmp common_syscall
section .text.ktimer_create exec
global ktimer_create
ktimer_create:
mov eax, 235
jmp common_syscall
section .text.ktimer_delete exec
global ktimer_delete
ktimer_delete:
mov eax, 236
jmp common_syscall
section .text.ktimer_settime exec
global ktimer_settime
ktimer_settime:
mov eax, 237
jmp common_syscall
section .text.ktimer_gettime exec
global ktimer_gettime
ktimer_gettime:
mov eax, 238
jmp common_syscall
section .text.ktimer_getoverrun exec
global ktimer_getoverrun
ktimer_getoverrun:
mov eax, 239
jmp common_syscall
section .text.nanosleep exec
global nanosleep
nanosleep:
mov eax, 240
jmp common_syscall
section .text.clock_getcpuclockid2 exec
global clock_getcpuclockid2
clock_getcpuclockid2:
mov eax, 247
jmp common_syscall
section .text.ntp_gettime exec
global ntp_gettime
ntp_gettime:
mov eax, 248
jmp common_syscall
section .text.minherit exec
global minherit
minherit:
mov eax, 250
jmp common_syscall
section .text.rfork exec
global rfork
rfork:
mov eax, 251
jmp common_syscall
section .text.openbsd_poll exec
global openbsd_poll
openbsd_poll:
mov eax, 252
jmp common_syscall
section .text.issetugid exec
global issetugid
issetugid:
mov eax, 253
jmp common_syscall
section .text.lchown exec
global lchown
lchown:
mov eax, 254
jmp common_syscall
section .text.getdents exec
global getdents
getdents:
mov eax, 272
jmp common_syscall
section .text.lchmod exec
global lchmod
lchmod:
mov eax, 274
jmp common_syscall
section .text.lutimes exec
global lutimes
lutimes:
mov eax, 276
jmp common_syscall
section .text.nstat exec
global nstat
nstat:
mov eax, 278
jmp common_syscall
section .text.nfstat exec
global nfstat
nfstat:
mov eax, 279
jmp common_syscall
section .text.nlstat exec
global nlstat
nlstat:
mov eax, 280
jmp common_syscall
section .text.preadv exec
global preadv
preadv:
mov eax, 289
jmp common_syscall
section .text.pwritev exec
global pwritev
pwritev:
mov eax, 290
jmp common_syscall
section .text.fhopen exec
global fhopen
fhopen:
mov eax, 298
jmp common_syscall
section .text.fhstat exec
global fhstat
fhstat:
mov eax, 299
jmp common_syscall
section .text.modnext exec
global modnext
modnext:
mov eax, 300
jmp common_syscall
section .text.modstat exec
global modstat
modstat:
mov eax, 301
jmp common_syscall
section .text.modfnext exec
global modfnext
modfnext:
mov eax, 302
jmp common_syscall
section .text.modfind exec
global modfind
modfind:
mov eax, 303
jmp common_syscall
section .text.kldload exec
global kldload
kldload:
mov eax, 304
jmp common_syscall
section .text.kldunload exec
global kldunload
kldunload:
mov eax, 305
jmp common_syscall
section .text.kldfind exec
global kldfind
kldfind:
mov eax, 306
jmp common_syscall
section .text.kldnext exec
global kldnext
kldnext:
mov eax, 307
jmp common_syscall
section .text.kldstat exec
global kldstat
kldstat:
mov eax, 308
jmp common_syscall
section .text.kldfirstmod exec
global kldfirstmod
kldfirstmod:
mov eax, 309
jmp common_syscall
section .text.getsid exec
global getsid
getsid:
mov eax, 310
jmp common_syscall
section .text.setresuid exec
global setresuid
setresuid:
mov eax, 311
jmp common_syscall
section .text.setresgid exec
global setresgid
setresgid:
mov eax, 312
jmp common_syscall
section .text.yield exec
global yield
yield:
mov eax, 321
jmp common_syscall
section .text.mlockall exec
global mlockall
mlockall:
mov eax, 324
jmp common_syscall
section .text.munlockall exec
global munlockall
munlockall:
mov eax, 325
jmp common_syscall
section .text.__getcwd exec
global __getcwd
__getcwd:
mov eax, 326
jmp common_syscall
section .text.sched_setparam exec
global sched_setparam
sched_setparam:
mov eax, 327
jmp common_syscall
section .text.sched_getparam exec
global sched_getparam
sched_getparam:
mov eax, 328
jmp common_syscall
section .text.sched_setscheduler exec
global sched_setscheduler
sched_setscheduler:
mov eax, 329
jmp common_syscall
section .text.sched_getscheduler exec
global sched_getscheduler
sched_getscheduler:
mov eax, 330
jmp common_syscall
section .text.sched_yield exec
global sched_yield
sched_yield:
mov eax, 331
jmp common_syscall
section .text.sched_get_priority_max exec
global sched_get_priority_max
sched_get_priority_max:
mov eax, 332
jmp common_syscall
section .text.sched_get_priority_min exec
global sched_get_priority_min
sched_get_priority_min:
mov eax, 333
jmp common_syscall
section .text.sched_rr_get_interval exec
global sched_rr_get_interval
sched_rr_get_interval:
mov eax, 334
jmp common_syscall
section .text.utrace exec
global utrace
utrace:
mov eax, 335
jmp common_syscall
section .text.kldsym exec
global kldsym
kldsym:
mov eax, 337
jmp common_syscall
section .text.jail exec
global jail
jail:
mov eax, 338
jmp common_syscall
section .text.sigprocmask exec
global sigprocmask
sigprocmask:
mov eax, 340
jmp common_syscall
section .text.sigsuspend exec
global sigsuspend
sigsuspend:
mov eax, 341
jmp common_syscall
section .text.sigpending exec
global sigpending
sigpending:
mov eax, 343
jmp common_syscall
section .text.sigtimedwait exec
global sigtimedwait
sigtimedwait:
mov eax, 345
jmp common_syscall
section .text.sigwaitinfo exec
global sigwaitinfo
sigwaitinfo:
mov eax, 346
jmp common_syscall
section .text.__acl_get_file exec
global __acl_get_file
__acl_get_file:
mov eax, 347
jmp common_syscall
section .text.__acl_set_file exec
global __acl_set_file
__acl_set_file:
mov eax, 348
jmp common_syscall
section .text.__acl_get_fd exec
global __acl_get_fd
__acl_get_fd:
mov eax, 349
jmp common_syscall
section .text.__acl_set_fd exec
global __acl_set_fd
__acl_set_fd:
mov eax, 350
jmp common_syscall
section .text.__acl_delete_file exec
global __acl_delete_file
__acl_delete_file:
mov eax, 351
jmp common_syscall
section .text.__acl_delete_fd exec
global __acl_delete_fd
__acl_delete_fd:
mov eax, 352
jmp common_syscall
section .text.__acl_aclcheck_file exec
global __acl_aclcheck_file
__acl_aclcheck_file:
mov eax, 353
jmp common_syscall
section .text.__acl_aclcheck_fd exec
global __acl_aclcheck_fd
__acl_aclcheck_fd:
mov eax, 354
jmp common_syscall
section .text.extattrctl exec
global extattrctl
extattrctl:
mov eax, 355
jmp common_syscall
section .text.extattr_set_file exec
global extattr_set_file
extattr_set_file:
mov eax, 356
jmp common_syscall
section .text.extattr_get_file exec
global extattr_get_file
extattr_get_file:
mov eax, 357
jmp common_syscall
section .text.extattr_delete_file exec
global extattr_delete_file
extattr_delete_file:
mov eax, 358
jmp common_syscall
section .text.getresuid exec
global getresuid
getresuid:
mov eax, 360
jmp common_syscall
section .text.getresgid exec
global getresgid
getresgid:
mov eax, 361
jmp common_syscall
section .text.kqueue exec
global kqueue
kqueue:
mov eax, 362
jmp common_syscall
section .text.kevent exec
global kevent
kevent:
mov eax, 363
jmp common_syscall
section .text.extattr_set_fd exec
global extattr_set_fd
extattr_set_fd:
mov eax, 371
jmp common_syscall
section .text.extattr_get_fd exec
global extattr_get_fd
extattr_get_fd:
mov eax, 372
jmp common_syscall
section .text.extattr_delete_fd exec
global extattr_delete_fd
extattr_delete_fd:
mov eax, 373
jmp common_syscall
section .text.__setugid exec
global __setugid
__setugid:
mov eax, 374
jmp common_syscall
section .text.eaccess exec
global eaccess
eaccess:
mov eax, 376
jmp common_syscall
section .text.nmount exec
global nmount
nmount:
mov eax, 378
jmp common_syscall
section .text.mtypeprotect exec
global mtypeprotect
mtypeprotect:
mov eax, 379
jmp common_syscall
section .text.__mac_get_proc exec
global __mac_get_proc
__mac_get_proc:
mov eax, 384
jmp common_syscall
section .text.__mac_set_proc exec
global __mac_set_proc
__mac_set_proc:
mov eax, 385
jmp common_syscall
section .text.__mac_get_fd exec
global __mac_get_fd
__mac_get_fd:
mov eax, 386
jmp common_syscall
section .text.__mac_get_file exec
global __mac_get_file
__mac_get_file:
mov eax, 387
jmp common_syscall
section .text.__mac_set_fd exec
global __mac_set_fd
__mac_set_fd:
mov eax, 388
jmp common_syscall
section .text.__mac_set_file exec
global __mac_set_file
__mac_set_file:
mov eax, 389
jmp common_syscall
section .text.kenv exec
global kenv
kenv:
mov eax, 390
jmp common_syscall
section .text.lchflags exec
global lchflags
lchflags:
mov eax, 391
jmp common_syscall
section .text.uuidgen exec
global uuidgen
uuidgen:
mov eax, 392
jmp common_syscall
section .text.sendfile exec
global sendfile
sendfile:
mov eax, 393
jmp common_syscall
section .text.mac_syscall exec
global mac_syscall
mac_syscall:
mov eax, 394
jmp common_syscall
section .text.getfsstat exec
global getfsstat
getfsstat:
mov eax, 395
jmp common_syscall
section .text.statfs exec
global statfs
statfs:
mov eax, 396
jmp common_syscall
section .text.fstatfs exec
global fstatfs
fstatfs:
mov eax, 397
jmp common_syscall
section .text.fhstatfs exec
global fhstatfs
fhstatfs:
mov eax, 398
jmp common_syscall
section .text.__mac_get_pid exec
global __mac_get_pid
__mac_get_pid:
mov eax, 409
jmp common_syscall
section .text.__mac_get_link exec
global __mac_get_link
__mac_get_link:
mov eax, 410
jmp common_syscall
section .text.__mac_set_link exec
global __mac_set_link
__mac_set_link:
mov eax, 411
jmp common_syscall
section .text.extattr_set_link exec
global extattr_set_link
extattr_set_link:
mov eax, 412
jmp common_syscall
section .text.extattr_get_link exec
global extattr_get_link
extattr_get_link:
mov eax, 413
jmp common_syscall
section .text.extattr_delete_link exec
global extattr_delete_link
extattr_delete_link:
mov eax, 414
jmp common_syscall
section .text.__mac_execve exec
global __mac_execve
__mac_execve:
mov eax, 415
jmp common_syscall
section .text.sigaction exec
global sigaction
sigaction:
mov eax, 416
jmp common_syscall
section .text.sigreturn exec
global sigreturn
sigreturn:
mov eax, 417
jmp common_syscall
section .text.getcontext exec
global getcontext
getcontext:
mov eax, 421
jmp common_syscall
section .text.setcontext exec
global setcontext
setcontext:
mov eax, 422
jmp common_syscall
section .text.swapcontext exec
global swapcontext
swapcontext:
mov eax, 423
jmp common_syscall
section .text.swapoff exec
global swapoff
swapoff:
mov eax, 424
jmp common_syscall
section .text.__acl_get_link exec
global __acl_get_link
__acl_get_link:
mov eax, 425
jmp common_syscall
section .text.__acl_set_link exec
global __acl_set_link
__acl_set_link:
mov eax, 426
jmp common_syscall
section .text.__acl_delete_link exec
global __acl_delete_link
__acl_delete_link:
mov eax, 427
jmp common_syscall
section .text.__acl_aclcheck_link exec
global __acl_aclcheck_link
__acl_aclcheck_link:
mov eax, 428
jmp common_syscall
section .text.sigwait exec
global sigwait
sigwait:
mov eax, 429
jmp common_syscall
section .text.thr_create exec
global thr_create
thr_create:
mov eax, 430
jmp common_syscall
section .text.thr_exit exec
global thr_exit
thr_exit:
mov eax, 431
jmp common_syscall
section .text.thr_self exec
global thr_self
thr_self:
mov eax, 432
jmp common_syscall
section .text.thr_kill exec
global thr_kill
thr_kill:
mov eax, 433
jmp common_syscall
section .text._umtx_lock exec
global _umtx_lock
_umtx_lock:
mov eax, 434
jmp common_syscall
section .text._umtx_unlock exec
global _umtx_unlock
_umtx_unlock:
mov eax, 435
jmp common_syscall
section .text.jail_attach exec
global jail_attach
jail_attach:
mov eax, 436
jmp common_syscall
section .text.extattr_list_fd exec
global extattr_list_fd
extattr_list_fd:
mov eax, 437
jmp common_syscall
section .text.extattr_list_file exec
global extattr_list_file
extattr_list_file:
mov eax, 438
jmp common_syscall
section .text.extattr_list_link exec
global extattr_list_link
extattr_list_link:
mov eax, 439
jmp common_syscall
section .text.thr_suspend exec
global thr_suspend
thr_suspend:
mov eax, 442
jmp common_syscall
section .text.thr_wake exec
global thr_wake
thr_wake:
mov eax, 443
jmp common_syscall
section .text.kldunloadf exec
global kldunloadf
kldunloadf:
mov eax, 444
jmp common_syscall
section .text.audit exec
global audit
audit:
mov eax, 445
jmp common_syscall
section .text.auditon exec
global auditon
auditon:
mov eax, 446
jmp common_syscall
section .text.getauid exec
global getauid
getauid:
mov eax, 447
jmp common_syscall
section .text.setauid exec
global setauid
setauid:
mov eax, 448
jmp common_syscall
section .text.getaudit exec
global getaudit
getaudit:
mov eax, 449
jmp common_syscall
section .text.setaudit exec
global setaudit
setaudit:
mov eax, 450
jmp common_syscall
section .text.getaudit_addr exec
global getaudit_addr
getaudit_addr:
mov eax, 451
jmp common_syscall
section .text.setaudit_addr exec
global setaudit_addr
setaudit_addr:
mov eax, 452
jmp common_syscall
section .text.auditctl exec
global auditctl
auditctl:
mov eax, 453
jmp common_syscall
section .text._umtx_op exec
global _umtx_op
_umtx_op:
mov eax, 454
jmp common_syscall
section .text.thr_new exec
global thr_new
thr_new:
mov eax, 455
jmp common_syscall
section .text.sigqueue exec
global sigqueue
sigqueue:
mov eax, 456
jmp common_syscall
section .text.abort2 exec
global abort2
abort2:
mov eax, 463
jmp common_syscall
section .text.thr_set_name exec
global thr_set_name
thr_set_name:
mov eax, 464
jmp common_syscall
section .text.rtprio_thread exec
global rtprio_thread
rtprio_thread:
mov eax, 466
jmp common_syscall
section .text.sctp_peeloff exec
global sctp_peeloff
sctp_peeloff:
mov eax, 471
jmp common_syscall
section .text.sctp_generic_sendmsg exec
global sctp_generic_sendmsg
sctp_generic_sendmsg:
mov eax, 472
jmp common_syscall
section .text.sctp_generic_sendmsg_iov exec
global sctp_generic_sendmsg_iov
sctp_generic_sendmsg_iov:
mov eax, 473
jmp common_syscall
section .text.sctp_generic_recvmsg exec
global sctp_generic_recvmsg
sctp_generic_recvmsg:
mov eax, 474
jmp common_syscall
section .text.pread exec
global pread
pread:
mov eax, 475
jmp common_syscall
section .text.pwrite exec
global pwrite
pwrite:
mov eax, 476
jmp common_syscall
section .text.mmap exec
global mmap
mmap:
mov eax, 477
jmp common_syscall
section .text.lseek exec
global lseek
lseek:
mov eax, 478
jmp common_syscall
section .text.truncate exec
global truncate
truncate:
mov eax, 479
jmp common_syscall
section .text.ftruncate exec
global ftruncate
ftruncate:
mov eax, 480
jmp common_syscall
section .text.thr_kill2 exec
global thr_kill2
thr_kill2:
mov eax, 481
jmp common_syscall
section .text.shm_open exec
global shm_open
shm_open:
mov eax, 482
jmp common_syscall
section .text.shm_unlink exec
global shm_unlink
shm_unlink:
mov eax, 483
jmp common_syscall
section .text.cpuset exec
global cpuset
cpuset:
mov eax, 484
jmp common_syscall
section .text.cpuset_setid exec
global cpuset_setid
cpuset_setid:
mov eax, 485
jmp common_syscall
section .text.cpuset_getid exec
global cpuset_getid
cpuset_getid:
mov eax, 486
jmp common_syscall
section .text.cpuset_getaffinity exec
global cpuset_getaffinity
cpuset_getaffinity:
mov eax, 487
jmp common_syscall
section .text.cpuset_setaffinity exec
global cpuset_setaffinity
cpuset_setaffinity:
mov eax, 488
jmp common_syscall
section .text.faccessat exec
global faccessat
faccessat:
mov eax, 489
jmp common_syscall
section .text.fchmodat exec
global fchmodat
fchmodat:
mov eax, 490
jmp common_syscall
section .text.fchownat exec
global fchownat
fchownat:
mov eax, 491
jmp common_syscall
section .text.fexecve exec
global fexecve
fexecve:
mov eax, 492
jmp common_syscall
section .text.fstatat exec
global fstatat
fstatat:
mov eax, 493
jmp common_syscall
section .text.futimesat exec
global futimesat
futimesat:
mov eax, 494
jmp common_syscall
section .text.linkat exec
global linkat
linkat:
mov eax, 495
jmp common_syscall
section .text.mkdirat exec
global mkdirat
mkdirat:
mov eax, 496
jmp common_syscall
section .text.mkfifoat exec
global mkfifoat
mkfifoat:
mov eax, 497
jmp common_syscall
section .text.mknodat exec
global mknodat
mknodat:
mov eax, 498
jmp common_syscall
section .text.openat exec
global openat
openat:
mov eax, 499
jmp common_syscall
section .text.readlinkat exec
global readlinkat
readlinkat:
mov eax, 500
jmp common_syscall
section .text.renameat exec
global renameat
renameat:
mov eax, 501
jmp common_syscall
section .text.symlinkat exec
global symlinkat
symlinkat:
mov eax, 502
jmp common_syscall
section .text.unlinkat exec
global unlinkat
unlinkat:
mov eax, 503
jmp common_syscall
section .text.posix_openpt exec
global posix_openpt
posix_openpt:
mov eax, 504
jmp common_syscall
section .text.jail_get exec
global jail_get
jail_get:
mov eax, 506
jmp common_syscall
section .text.jail_set exec
global jail_set
jail_set:
mov eax, 507
jmp common_syscall
section .text.jail_remove exec
global jail_remove
jail_remove:
mov eax, 508
jmp common_syscall
section .text.closefrom exec
global closefrom
closefrom:
mov eax, 509
jmp common_syscall
section .text.lpathconf exec
global lpathconf
lpathconf:
mov eax, 513
jmp common_syscall
section .text.cap_new exec
global cap_new
cap_new:
mov eax, 514
jmp common_syscall
section .text.cap_getrights exec
global cap_getrights
cap_getrights:
mov eax, 515
jmp common_syscall
section .text.cap_enter exec
global cap_enter
cap_enter:
mov eax, 516
jmp common_syscall
section .text.cap_getmode exec
global cap_getmode
cap_getmode:
mov eax, 517
jmp common_syscall
section .text.pdfork exec
global pdfork
pdfork:
mov eax, 518
jmp common_syscall
section .text.pdkill exec
global pdkill
pdkill:
mov eax, 519
jmp common_syscall
section .text.pdgetpid exec
global pdgetpid
pdgetpid:
mov eax, 520
jmp common_syscall
section .text.pselect exec
global pselect
pselect:
mov eax, 522
jmp common_syscall
section .text.getloginclass exec
global getloginclass
getloginclass:
mov eax, 523
jmp common_syscall
section .text.setloginclass exec
global setloginclass
setloginclass:
mov eax, 524
jmp common_syscall
section .text.rctl_get_racct exec
global rctl_get_racct
rctl_get_racct:
mov eax, 525
jmp common_syscall
section .text.rctl_get_rules exec
global rctl_get_rules
rctl_get_rules:
mov eax, 526
jmp common_syscall
section .text.rctl_get_limits exec
global rctl_get_limits
rctl_get_limits:
mov eax, 527
jmp common_syscall
section .text.rctl_add_rule exec
global rctl_add_rule
rctl_add_rule:
mov eax, 528
jmp common_syscall
section .text.rctl_remove_rule exec
global rctl_remove_rule
rctl_remove_rule:
mov eax, 529
jmp common_syscall
section .text.posix_fallocate exec
global posix_fallocate
posix_fallocate:
mov eax, 530
jmp common_syscall
section .text.posix_fadvise exec
global posix_fadvise
posix_fadvise:
mov eax, 531
jmp common_syscall
section .text.regmgr_call exec
global regmgr_call
regmgr_call:
mov eax, 532
jmp common_syscall
section .text.jitshm_create exec
global jitshm_create
jitshm_create:
mov eax, 533
jmp common_syscall
section .text.jitshm_alias exec
global jitshm_alias
jitshm_alias:
mov eax, 534
jmp common_syscall
section .text.dl_get_list exec
global dl_get_list
dl_get_list:
mov eax, 535
jmp common_syscall
section .text.dl_get_info exec
global dl_get_info
dl_get_info:
mov eax, 536
jmp common_syscall
section .text.dl_notify_event exec
global dl_notify_event
dl_notify_event:
mov eax, 537
jmp common_syscall
section .text.evf_create exec
global evf_create
evf_create:
mov eax, 538
jmp common_syscall
section .text.evf_delete exec
global evf_delete
evf_delete:
mov eax, 539
jmp common_syscall
section .text.evf_open exec
global evf_open
evf_open:
mov eax, 540
jmp common_syscall
section .text.evf_close exec
global evf_close
evf_close:
mov eax, 541
jmp common_syscall
section .text.evf_wait exec
global evf_wait
evf_wait:
mov eax, 542
jmp common_syscall
section .text.evf_trywait exec
global evf_trywait
evf_trywait:
mov eax, 543
jmp common_syscall
section .text.evf_set exec
global evf_set
evf_set:
mov eax, 544
jmp common_syscall
section .text.evf_clear exec
global evf_clear
evf_clear:
mov eax, 545
jmp common_syscall
section .text.evf_cancel exec
global evf_cancel
evf_cancel:
mov eax, 546
jmp common_syscall
section .text.query_memory_protection exec
global query_memory_protection
query_memory_protection:
mov eax, 547
jmp common_syscall
section .text.batch_map exec
global batch_map
batch_map:
mov eax, 548
jmp common_syscall
section .text.osem_create exec
global osem_create
osem_create:
mov eax, 549
jmp common_syscall
section .text.osem_delete exec
global osem_delete
osem_delete:
mov eax, 550
jmp common_syscall
section .text.osem_open exec
global osem_open
osem_open:
mov eax, 551
jmp common_syscall
section .text.osem_close exec
global osem_close
osem_close:
mov eax, 552
jmp common_syscall
section .text.osem_wait exec
global osem_wait
osem_wait:
mov eax, 553
jmp common_syscall
section .text.osem_trywait exec
global osem_trywait
osem_trywait:
mov eax, 554
jmp common_syscall
section .text.osem_post exec
global osem_post
osem_post:
mov eax, 555
jmp common_syscall
section .text.osem_cancel exec
global osem_cancel
osem_cancel:
mov eax, 556
jmp common_syscall
section .text.namedobj_create exec
global namedobj_create
namedobj_create:
mov eax, 557
jmp common_syscall
section .text.namedobj_delete exec
global namedobj_delete
namedobj_delete:
mov eax, 558
jmp common_syscall
section .text.set_vm_container exec
global set_vm_container
set_vm_container:
mov eax, 559
jmp common_syscall
section .text.debug_init exec
global debug_init
debug_init:
mov eax, 560
jmp common_syscall
section .text.suspend_process exec
global suspend_process
suspend_process:
mov eax, 561
jmp common_syscall
section .text.resume_process exec
global resume_process
resume_process:
mov eax, 562
jmp common_syscall
section .text.opmc_enable exec
global opmc_enable
opmc_enable:
mov eax, 563
jmp common_syscall
section .text.opmc_disable exec
global opmc_disable
opmc_disable:
mov eax, 564
jmp common_syscall
section .text.opmc_set_ctl exec
global opmc_set_ctl
opmc_set_ctl:
mov eax, 565
jmp common_syscall
section .text.opmc_set_ctr exec
global opmc_set_ctr
opmc_set_ctr:
mov eax, 566
jmp common_syscall
section .text.opmc_get_ctr exec
global opmc_get_ctr
opmc_get_ctr:
mov eax, 567
jmp common_syscall
section .text.budget_create exec
global budget_create
budget_create:
mov eax, 568
jmp common_syscall
section .text.budget_delete exec
global budget_delete
budget_delete:
mov eax, 569
jmp common_syscall
section .text.budget_get exec
global budget_get
budget_get:
mov eax, 570
jmp common_syscall
section .text.budget_set exec
global budget_set
budget_set:
mov eax, 571
jmp common_syscall
section .text.virtual_query exec
global virtual_query
virtual_query:
mov eax, 572
jmp common_syscall
section .text.mdbg_call exec
global mdbg_call
mdbg_call:
mov eax, 573
jmp common_syscall
section .text.sblock_create exec
global sblock_create
sblock_create:
mov eax, 574
jmp common_syscall
section .text.sblock_delete exec
global sblock_delete
sblock_delete:
mov eax, 575
jmp common_syscall
section .text.sblock_enter exec
global sblock_enter
sblock_enter:
mov eax, 576
jmp common_syscall
section .text.sblock_exit exec
global sblock_exit
sblock_exit:
mov eax, 577
jmp common_syscall
section .text.sblock_xenter exec
global sblock_xenter
sblock_xenter:
mov eax, 578
jmp common_syscall
section .text.sblock_xexit exec
global sblock_xexit
sblock_xexit:
mov eax, 579
jmp common_syscall
section .text.eport_create exec
global eport_create
eport_create:
mov eax, 580
jmp common_syscall
section .text.eport_delete exec
global eport_delete
eport_delete:
mov eax, 581
jmp common_syscall
section .text.eport_trigger exec
global eport_trigger
eport_trigger:
mov eax, 582
jmp common_syscall
section .text.eport_open exec
global eport_open
eport_open:
mov eax, 583
jmp common_syscall
section .text.eport_close exec
global eport_close
eport_close:
mov eax, 584
jmp common_syscall
section .text.is_in_sandbox exec
global is_in_sandbox
is_in_sandbox:
mov eax, 585
jmp common_syscall
section .text.dmem_container exec
global dmem_container
dmem_container:
mov eax, 586
jmp common_syscall
section .text.get_authinfo exec
global get_authinfo
get_authinfo:
mov eax, 587
jmp common_syscall
section .text.mname exec
global mname
mname:
mov eax, 588
jmp common_syscall
section .text.dynlib_dlopen exec
global dynlib_dlopen
dynlib_dlopen:
mov eax, 589
jmp common_syscall
section .text.dynlib_dlclose exec
global dynlib_dlclose
dynlib_dlclose:
mov eax, 590
jmp common_syscall
section .text.dynlib_dlsym exec
global dynlib_dlsym
dynlib_dlsym:
mov eax, 591
jmp common_syscall
section .text.dynlib_get_list exec
global dynlib_get_list
dynlib_get_list:
mov eax, 592
jmp common_syscall
section .text.dynlib_get_info exec
global dynlib_get_info
dynlib_get_info:
mov eax, 593
jmp common_syscall
section .text.dynlib_load_prx exec
global dynlib_load_prx
dynlib_load_prx:
mov eax, 594
jmp common_syscall
section .text.dynlib_unload_prx exec
global dynlib_unload_prx
dynlib_unload_prx:
mov eax, 595
jmp common_syscall
section .text.dynlib_do_copy_relocations exec
global dynlib_do_copy_relocations
dynlib_do_copy_relocations:
mov eax, 596
jmp common_syscall
section .text.dynlib_prepare_dlclose exec
global dynlib_prepare_dlclose
dynlib_prepare_dlclose:
mov eax, 597
jmp common_syscall
section .text.dynlib_get_proc_param exec
global dynlib_get_proc_param
dynlib_get_proc_param:
mov eax, 598
jmp common_syscall
section .text.dynlib_process_needed_and_relocate exec
global dynlib_process_needed_and_relocate
dynlib_process_needed_and_relocate:
mov eax, 599
jmp common_syscall
section .text.sandbox_path exec
global sandbox_path
sandbox_path:
mov eax, 600
jmp common_syscall
section .text.mdbg_service exec
global mdbg_service
mdbg_service:
mov eax, 601
jmp common_syscall
section .text.randomized_path exec
global randomized_path
randomized_path:
mov eax, 602
jmp common_syscall
section .text.rdup exec
global rdup
rdup:
mov eax, 603
jmp common_syscall
section .text.dl_get_metadata exec
global dl_get_metadata
dl_get_metadata:
mov eax, 604
jmp common_syscall
section .text.workaround8849 exec
global workaround8849
workaround8849:
mov eax, 605
jmp common_syscall
section .text.is_development_mode exec
global is_development_mode
is_development_mode:
mov eax, 606
jmp common_syscall
section .text.get_self_auth_info exec
global get_self_auth_info
get_self_auth_info:
mov eax, 607
jmp common_syscall
section .text.dynlib_get_info_ex exec
global dynlib_get_info_ex
dynlib_get_info_ex:
mov eax, 608
jmp common_syscall
section .text.budget_getid exec
global budget_getid
budget_getid:
mov eax, 609
jmp common_syscall
section .text.budget_get_ptype exec
global budget_get_ptype
budget_get_ptype:
mov eax, 610
jmp common_syscall
section .text.get_paging_stats_of_all_threads exec
global get_paging_stats_of_all_threads
get_paging_stats_of_all_threads:
mov eax, 611
jmp common_syscall
section .text.get_proc_type_info exec
global get_proc_type_info
get_proc_type_info:
mov eax, 612
jmp common_syscall
section .text.get_resident_count exec
global get_resident_count
get_resident_count:
mov eax, 613
jmp common_syscall
section .text.prepare_to_suspend_process exec
global prepare_to_suspend_process
prepare_to_suspend_process:
mov eax, 614
jmp common_syscall
section .text.get_resident_fmem_count exec
global get_resident_fmem_count
get_resident_fmem_count:
mov eax, 615
jmp common_syscall
section .text.thr_get_name exec
global thr_get_name
thr_get_name:
mov eax, 616
jmp common_syscall
section .text.set_gpo exec
global set_gpo
set_gpo:
mov eax, 617
jmp common_syscall
section .text.get_paging_stats_of_all_objects exec
global get_paging_stats_of_all_objects
get_paging_stats_of_all_objects:
mov eax, 618
jmp common_syscall
section .text.test_debug_rwmem exec
global test_debug_rwmem
test_debug_rwmem:
mov eax, 619
jmp common_syscall
section .text.free_stack exec
global free_stack
free_stack:
mov eax, 620
jmp common_syscall
section .text.suspend_system exec
global suspend_system
suspend_system:
mov eax, 621
jmp common_syscall
section .text.ipmimgr_call exec
global ipmimgr_call
ipmimgr_call:
mov eax, 622
jmp common_syscall
section .text.get_gpo exec
global get_gpo
get_gpo:
mov eax, 623
jmp common_syscall
section .text.get_vm_map_timestamp exec
global get_vm_map_timestamp
get_vm_map_timestamp:
mov eax, 624
jmp common_syscall
section .text.opmc_set_hw exec
global opmc_set_hw
opmc_set_hw:
mov eax, 625
jmp common_syscall
section .text.opmc_get_hw exec
global opmc_get_hw
opmc_get_hw:
mov eax, 626
jmp common_syscall
section .text.get_cpu_usage_all exec
global get_cpu_usage_all
get_cpu_usage_all:
mov eax, 627
jmp common_syscall
section .text.mmap_dmem exec
global mmap_dmem
mmap_dmem:
mov eax, 628
jmp common_syscall
section .text.physhm_open exec
global physhm_open
physhm_open:
mov eax, 629
jmp common_syscall
section .text.physhm_unlink exec
global physhm_unlink
physhm_unlink:
mov eax, 630
jmp common_syscall
section .text.resume_internal_hdd exec
global resume_internal_hdd
resume_internal_hdd:
mov eax, 631
jmp common_syscall
section .text.thr_suspend_ucontext exec
global thr_suspend_ucontext
thr_suspend_ucontext:
mov eax, 632
jmp common_syscall
section .text.thr_resume_ucontext exec
global thr_resume_ucontext
thr_resume_ucontext:
mov eax, 633
jmp common_syscall
section .text.thr_get_ucontext exec
global thr_get_ucontext
thr_get_ucontext:
mov eax, 634
jmp common_syscall
section .text.thr_set_ucontext exec
global thr_set_ucontext
thr_set_ucontext:
mov eax, 635
jmp common_syscall
section .text.set_timezone_info exec
global set_timezone_info
set_timezone_info:
mov eax, 636
jmp common_syscall
section .text.set_phys_fmem_limit exec
global set_phys_fmem_limit
set_phys_fmem_limit:
mov eax, 637
jmp common_syscall
section .text.utc_to_localtime exec
global utc_to_localtime
utc_to_localtime:
mov eax, 638
jmp common_syscall
section .text.localtime_to_utc exec
global localtime_to_utc
localtime_to_utc:
mov eax, 639
jmp common_syscall
section .text.set_uevt exec
global set_uevt
set_uevt:
mov eax, 640
jmp common_syscall
section .text.get_cpu_usage_proc exec
global get_cpu_usage_proc
get_cpu_usage_proc:
mov eax, 641
jmp common_syscall
section .text.get_map_statistics exec
global get_map_statistics
get_map_statistics:
mov eax, 642
jmp common_syscall
section .text.set_chicken_switches exec
global set_chicken_switches
set_chicken_switches:
mov eax, 643
jmp common_syscall
section .text.extend_page_table_pool exec
global extend_page_table_pool
extend_page_table_pool:
mov eax, 644
jmp common_syscall
section .text.extend_page_table_pool2 exec
global extend_page_table_pool2
extend_page_table_pool2:
mov eax, 645
jmp common_syscall
section .text.get_kernel_mem_statistics exec
global get_kernel_mem_statistics
get_kernel_mem_statistics:
mov eax, 646
jmp common_syscall
section .text.get_sdk_compiled_version exec
global get_sdk_compiled_version
get_sdk_compiled_version:
mov eax, 647
jmp common_syscall
section .text.app_state_change exec
global app_state_change
app_state_change:
mov eax, 648
jmp common_syscall
section .text.dynlib_get_obj_member exec
global dynlib_get_obj_member
dynlib_get_obj_member:
mov eax, 649
jmp common_syscall
section .text.budget_get_ptype_of_budget exec
global budget_get_ptype_of_budget
budget_get_ptype_of_budget:
mov eax, 650
jmp common_syscall
section .text.prepare_to_resume_process exec
global prepare_to_resume_process
prepare_to_resume_process:
mov eax, 651
jmp common_syscall
section .text.process_terminate exec
global process_terminate
process_terminate:
mov eax, 652
jmp common_syscall
section .text.blockpool_open exec
global blockpool_open
blockpool_open:
mov eax, 653
jmp common_syscall
section .text.blockpool_map exec
global blockpool_map
blockpool_map:
mov eax, 654
jmp common_syscall
section .text.blockpool_unmap exec
global blockpool_unmap
blockpool_unmap:
mov eax, 655
jmp common_syscall
section .text.dynlib_get_info_for_libdbg exec
global dynlib_get_info_for_libdbg
dynlib_get_info_for_libdbg:
mov eax, 656
jmp common_syscall
section .text.blockpool_batch exec
global blockpool_batch
blockpool_batch:
mov eax, 657
jmp common_syscall
section .text.fdatasync exec
global fdatasync
fdatasync:
mov eax, 658
jmp common_syscall
section .text.dynlib_get_list2 exec
global dynlib_get_list2
dynlib_get_list2:
mov eax, 659
jmp common_syscall
section .text.dynlib_get_info2 exec
global dynlib_get_info2
dynlib_get_info2:
mov eax, 660
jmp common_syscall
section .text.aio_submit exec
global aio_submit
aio_submit:
mov eax, 661
jmp common_syscall
section .text.aio_multi_delete exec
global aio_multi_delete
aio_multi_delete:
mov eax, 662
jmp common_syscall
section .text.aio_multi_wait exec
global aio_multi_wait
aio_multi_wait:
mov eax, 663
jmp common_syscall
section .text.aio_multi_poll exec
global aio_multi_poll
aio_multi_poll:
mov eax, 664
jmp common_syscall
section .text.aio_get_data exec
global aio_get_data
aio_get_data:
mov eax, 665
jmp common_syscall
section .text.aio_multi_cancel exec
global aio_multi_cancel
aio_multi_cancel:
mov eax, 666
jmp common_syscall
section .text.get_bio_usage_all exec
global get_bio_usage_all
get_bio_usage_all:
mov eax, 667
jmp common_syscall
section .text.aio_create exec
global aio_create
aio_create:
mov eax, 668
jmp common_syscall
section .text.aio_submit_cmd exec
global aio_submit_cmd
aio_submit_cmd:
mov eax, 669
jmp common_syscall
section .text.aio_init exec
global aio_init
aio_init:
mov eax, 670
jmp common_syscall
section .text.get_page_table_stats exec
global get_page_table_stats
get_page_table_stats:
mov eax, 671
jmp common_syscall
section .text.dynlib_get_list_for_libdbg exec
global dynlib_get_list_for_libdbg
dynlib_get_list_for_libdbg:
mov eax, 672
jmp common_syscall
section .text.blockpool_move exec
global blockpool_move
blockpool_move:
mov eax, 673
jmp common_syscall
section .text.virtual_query_all exec
global virtual_query_all
virtual_query_all:
mov eax, 674
jmp common_syscall
section .text.reserve_2mb_page exec
global reserve_2mb_page
reserve_2mb_page:
mov eax, 675
jmp common_syscall
section .text.cpumode_yield exec
global cpumode_yield
cpumode_yield:
mov eax, 676
jmp common_syscall
section .text.get_phys_page_size exec
global get_phys_page_size
get_phys_page_size:
mov eax, 677
jmp common_syscall
section .text.common_syscall exec
common_syscall:
mov r10, [rel p_syscall]
test r10, r10
jnz .jmp
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
push rax
mov r10, [rel addr__dynlib_dlsym]
push r10
mov edi, 0x1
lea rsi, [rel getpid_str]
mov rdx, rsp
call r10
pop r10
pop rax
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
add r10, 7
mov [rel p_syscall], r10
.jmp:
jmp r10

section .text.__error exec
global __error
__error:
mov r10, [rel addr____error]
test r10, r10
jnz .have_error
push rax
mov edi, 0x1
lea rsi, [rel error_str]
mov rdx, rsp
call [rel addr__dynlib_dlsym]
pop r10
.have_error:
jmp r10

section .text.syscall exec
global syscall
$syscall:
mov rax, rdi
mov rdi, rsi
mov rsi, rdx
mov rdx, rcx
mov rcx, r8
mov r8, r9
mov r9, [rsp+8]
jmp common_syscall

section .rodata.getpid_str
getpid_str:
db "getpid", 0

section .rodata.error_str
error_str:
db "__error", 0

section .bss.addr__dynlib_dlsym
global addr__dynlib_dlsym
addr__dynlib_dlsym:
dq 0

section .bss.addr____error
global addr____error
addr____error:
dq 0

section .bss.p_syscall
p_syscall:
dq 0
