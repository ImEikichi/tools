def get_hash(s: str) -> int:
    h = 0x5F3759DF

    for char in s:
        c = ord(char)
        if ord('A') <= c <= ord('Z'):
            c += 0x20  # tolower
        h = (h + c) & 0xFFFFFFFF
        h = (h + ((h << 7) & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h ^ (h >> 5)) & 0xFFFFFFFF

    h = (h + ((h << 3) & 0xFFFFFFFF)) & 0xFFFFFFFF
    h = (h ^ (h >> 13)) & 0xFFFFFFFF
    h = (h + ((h << 17) & 0xFFFFFFFF)) & 0xFFFFFFFF

    return h

targets = [
    "amsi.dll",
    "AmsiScanBuffer",
    "kernel32.dll",
    "ntdll.dll",
]

for t in targets:
    print(f"0x{get_hash(t):08X}  {t}")