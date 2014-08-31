
indirectCalls IDA Pro Plugin
----------------------------

The plugin was developed for the book "Reverse Engineering with IDA Pro". 

Description:
The indirectCalls plugin operates on ELF and PE IA-32 binaries. The plugin is used to help reverse engineer C++ binaries. C++ binaries present a challenge to the reverse engineer. This plugin attempts to help with C++'s use of indirect calls.

C++ code uses calls through registers as shown in the following assembly snippet :

.text:030876E4     mov     esi, [ecx]             ; esi = VTable
.text:030876E6     push    eax
.text:030876E7     call    dword ptr [esi+1Ch]    ; indirect call

The plugin also tracks indirect jumps such as:
jmp eax

The plugin and documentation refers to indirect calls and jumps as indirect calls for the sake of brevity.

Cross references are not created by IDA during analysis. The plugin sets breakpoints on all indirect calls, including indirect jumps. The binary is exercised by the debugger and any plugin set breakpoints are recorded. Options are available to create cross references and display a list of possible VTables.

Usage:
The plugin will have an entry under ( Edit | Plugins | indirectCalls). The plugin by default is bound to a hotkey (Alt-F7).

The current cursor address is used to determine which segment to plugin uses. Starting the plugin will bring up the following menu:

-----------------------------
(*) Run Debugger
( ) Only collect information
-----------------------------
[x] Display indirect call list
[x] Display BPs hit
[ ] Display cross segment BPs hit
[ ] Make the xrefs
[ ] Make the xrefs for cross segment calls
[x] Display possible vtables
[ ] Include non-offset(call [eax]) calls for vtables
-----------------------------

Radio button options:
Run the debugger - This option executes the program using the built in debugger. This option should not be used on unknown binaries without proper precautions. Process options under the Debugger need to configured.

Only collect information - This option only scans the binary for indirect calls. The 'Display indirect call list' checkbox must be selected, otherwise no information is presented to the user. All the other checkbox options are only valid when running under the debugger.

Checkbox options:
Display indirect call list - This option lists all indirect calls such as:
  jmp eax
  call ebx
  call [esi + 1Ch]
  
Display BPs hit - This option will list all indirect calls whose breakpoint was hit.

Display cross segment BPs hit - This options will also include breakpoints on indirect calls that span across segments. Cross segment calls are generally imports.

Make the xrefs - This option will create code cross references between the indirect call and the target.

Make the xrefs for cross segment calls - This option also creates cross references for targets belonging to a different segment than the caller.

Display possible vtables - The plugin attempts to calculate VTables by using the base register value in a call similar to the following:
  call [eax + 8h] ; this option assumes eax points to the base of a VTable  
  
Include non-offset(call [eax]) calls for vtables - This option will also include calls lacking offsets into VTable calculation. This option can lead to false positives as generally a VTable is rarely called once and only through the first function.

Note: By default the debugger displays messages whenever a breakpoint is hit. This behavior can slow down the plugin considerably. Debugger options are located under ( Debugger | Debugger options ... ).

Building:
The plugin builds with Visual Studio 2005/2008 including Express Editions. The project currently assumes the location of the SDK to be:
C:\SDK\idasdk51

If the SDK is in a different location a couple options need to be updated.
The options are located under the indirectCalls Property pages. Both of options listed below must be updated to reflect the location of the SDK.

 1.  C/C++  -> General -> Additional Include Directories
 2.  Linker -> General -> Additional Library Directories

NOTE: There is a bug in all versions of the SDK. One of the #includes in \include\intel.hpp needs to changed.
  from:  #include “../idaidp.hpp”
  to:    #include “../module/idaidp.hpp

Todo:
The plugin was written as a proof of concept. Many improvements can be made. 

The plugin should determine which segments are marked as executable code, rather than relying on the current cursor position.

The breakpoints can be changed to lower level code similar to Ilfak's code coverage plugin, (http://hexblog.com/2006/03/coverage_analyzer.html)

Exception handling is left to the user. 

Static analysis can be combined with the plugin to help reconstruct objects and determine inheritance. 

Changelog:
v.01 - Initial release for book

Contact:
Please contact me considering any bugs. 
http://jeru.ringzero.net/?page_id=3
