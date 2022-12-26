## Step 1: computer name

https://www.aldeid.com/wiki/Volatility/Retrieve-hostname

```
$ vol3 -f dump.vmem windows.registry.hivelist
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
Offset  FileFullPath    File output

0xf8a00000f010          Disabled
0xf8a000024010  \REGISTRY\MACHINE\SYSTEM        Disabled
0xf8a000053320  \REGISTRY\MACHINE\HARDWARE      Disabled
0xf8a000109410  \SystemRoot\System32\Config\SECURITY    Disabled
0xf8a00033d410  \Device\HarddiskVolume1\Boot\BCD        Disabled
0xf8a0005d5010  \SystemRoot\System32\Config\SOFTWARE    Disabled
0xf8a001495010  \SystemRoot\System32\Config\DEFAULT     Disabled
0xf8a0016d4010  \SystemRoot\System32\Config\SAM Disabled
0xf8a00175b010  \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT        Disabled
0xf8a00176e410  \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT  Disabled
0xf8a002090010  \??\C:\Users\Rick\ntuser.dat    Disabled
0xf8a0020ad410  \??\C:\Users\Rick\AppData\Local\Microsoft\Windows\UsrClass.dat  Disabled
0xf8a00377d2d0  \??\C:\System Volume Information\Syscache.hve   Disabled
```

```
$ vol3 -f dump.vmem windows.registry.printkey --offset 0xf8a000024010 --key 'ControlSet001\Control\ComputerName\ComputerName'
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
Last Write Time Hive Offset     Type    Key     Name    Data    Volatile

2018-06-02 19:23:00.000000      0xf8a000024010  REG_SZ  \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName        (Default)       "mnmsrvc"       False
2018-06-02 19:23:00.000000      0xf8a000024010  REG_SZ  \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName        ComputerName    "WIN-LO6FAF3DTFE"       False
```

computer name: ```WIN-LO6FAF3DTFE```

## Step 2: credentials

pwd hash may still give half of the points
hint: there are methods to get the plaintext hash without cracking it

https://www.aldeid.com/wiki/Volatility/Retrieve-password
```
$ vol3 -f dump.vmem windows.hashdump
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Rick    1000    aad3b435b51404eeaad3b435b51404ee        518172d012f97d3a8fcc089615283940
```

518172d012f97d3a8fcc089615283940 -> Rick's pwd

https://crackstation.net/ -> not found
https://cyberloginit.com/2017/12/26/hashcat-ntlm-brute-force.html

cracking it does not seem to be possible

https://security.stackexchange.com/a/113298
-> "it seems more than likely that the hash, or password, will also be stored in memory. In fact, there are quite a few password crackers that take your password directly from memory."

```
$ vol3 -f dump.vmem windows.lsadump
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
Key     Secret  Hex

DefaultPassword (MortyIsReallyAnOtter   28 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4d 00 6f 00 72 00 74 00 79 00 49 00 73 00 52 00 65 00 61 00 6c 00 6c 00 79 00 41 00 6e 00 4f 00 74 00 74 00 65 00 72 00 00 00 00 00 00 00 00 00
DPAPI_SYSTEM    ,6©Uá   àcL tcØ KEZä¼òw¥%?G
                                           åM¥È5ÏÜ      2c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 36 9b ba a9 55 e1 92 82 09 e0 63 4c 20 74 63 14 9e d8 a0 4b 45 87 5a e4 bc f2 77 a5 25 3f 47 12 0b e5 4d a5 c8 35 cf dc 00 00 00 00
```

Password: ```MortyIsReallyAnOtter```

Can be confirmed with: https://codebeautify.org/ntlm-hash-generator

## Step 3: Local network

```
vol3 -f dump.vmem windows.netscan
```

(see netscan.txt)

ip: ```192.168.202.131```

## Step 4: internet




## other

from ```windows.cmdline```:
```
3820	Rick And Morty	"C:\Torrents\Rick And Morty season 1 download.exe" 
```
Rock accidentely downloaded an executable instead of a video

from ```windows.cmdline```:
```
3304	notepad.exe	"C:\Windows\system32\NOTEPAD.EXE" C:\Users\Rick\Desktop\Flag.txt.WINDOWS
```
See what was in the open file ?
