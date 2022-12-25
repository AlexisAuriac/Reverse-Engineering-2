# Heroes of Migh and Magic III

We are trying to crack the game.

Text displayed when we run without a cd:
```
The Heroes III: The Shadow of Death CD-ROM was not found! 

The Shadow of Death requires a CD for Single Scenario Games, Campaign Games, and hosting Multi-player Games.

If you wish to join a Multi-player Game hosted by another player, a CD is not required, and you may proceed. 

If you wish to play a Single Scenario or a Campaign, please quit and insert the The Shadow of Death CD, before re-running The Shadow of Death.
```

## Solution

Tried getting strings from all files and searching for text from the pop-up, found nothing.

Early in the execution we can see a bunch of calls to:
- [CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) -> Opens I/O device
- [ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile) -> Reads data
- [GetFileType](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfiletype) -> checks file type
- [GetDriveTypeA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea) -> **checks what kind of drive it is (CD, Ram disk, removable media, etc...)**, probably what we are looking for


The problem is that it is called in a few places and it is hard to figure out where it decides if it should deactivate features.

To figure out where it should be removed I started replacing function calls with *nop* instructions, after some trial and error I found that the CD check can be bypassed by removing 2 function calls (HEROES3_cracked1.EXE).

I tried to get the same result by making smaller changes (reversing jump conditions, replacing GetDriveTypeA calls by ```mov eax, {DRIVE_CDROM}```, etc...) but haven't been able to make it work (yet?).
