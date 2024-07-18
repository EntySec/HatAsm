from hatasm import HatAsm

hatasm = HatAsm()
code = """
start:
    mov al, 0xa2
    syscall

    mov al, 0xa9
    mov edx, 0x1234567
    mov esi, 0x28121969
    mov edi, 0xfee1dead
    syscall
"""

result = hatasm.assemble('x64', code)

for line in hatasm.hexdump(result):
    print(line)
