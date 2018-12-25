# Gosecretsdump

Have you been using Impacket to dump hashes out of (large) NTDS.dit files, and become increasingly frustrated at how long it takes? I sure have!

All credit for the original code to the impacket devs, it's much more complicated than I anticipated.

This is a conversion of the impacket secretsdump module into golang. It's not very good, but it is quite fast. Please let me know if you find bugs, I'll try and fix where I can - bonus points if you can provide sample .dit files for me to bash against.

## Usage
You will need to obtain the NTDS.dit and SYSTEM file from the target domain controller as normal. This won't dump anything remotely, just local (for now at least).
```  
  -enabled
        Only output enabled accounts
  -ntds string
        Location of the NTDS file (required)
  -status
        Include status in hash output
  -system string
        Location of the SYSTEM file (required)
```

Example (there is a test .dit and system file in this repo)

`gosecretsdump -ntds test/ntds.dit -system test/system`