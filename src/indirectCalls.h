/*********************************************************************
* Indirect Call IDA Pro plugin
*
* Copyright (c) 2008 Luis Miras
* Licensed under the BSD License
*
*********************************************************************/

#ifndef INDIRECTCALLS_H_

#define INDIRECTCALLS_H_

#define NODE_COUNT -1
#define NNJMPxI 0x40
#define CNAMEOPT (GNCN_NOCOLOR | GNCN_NOFUNC | GNCN_NOLABEL)

struct dbgOptions;      //fwd declaration
struct indirectCallObj; //fwd declaration
typedef indirectCallObj indirect_t;
typedef qvector<ulong> bphitlist_t;

long vtEstimateSize(ea_t);
void idaapi vtDescription(void*, ulong, char*const *);
void idaapi vtEnter(void*, ulong);
void idaapi vtDestroy(void*);
void createVTableWindow(netnode* vtables);
void idaapi icDescription(void*, ulong, char*const *);
void idaapi icEnter(void*, ulong);
void idaapi icDestroy(void*);
ulong idaapi size(void*);
void createIndirectCallWindow(netnode*);
void idaapi ccDescription(void*, ulong, char*const *);
void idaapi ccEnter(void*, ulong);
void idaapi ccDestroy(void*);
ulong idaapi ccSize(void*);
void createCompletedBpWindow(netnode*, bphitlist_t*);
void requestSetBps(netnode*);
void setBps(netnode*);
void requestDelBps(netnode*);
void delBps(netnode*);
void setTargetXref(dbgOptions*, long, indirect_t*);
void addVTable(dbgOptions*, ea_t, indirect_t*);
int idaapi callback(void*, int, va_list);
void fillIndirectObj(indirect_t&);
bool setnodesize(netnode*, long);
long getnodesize(netnode*);
long getobjcount(netnode*);
void findIndirectCalls(segment_t*, netnode*);
void closeListWindows(void);
void register_event(ulong);
void run(int);
int init(void);
void term(void);

struct indirectCallObj
{
    ea_t caller; // indirect caller address
    ea_t target; // target address
    ea_t offset; // valid for call [reg+offset]
    // defaults to 0
    short call_reg; // enum REG
    short flags;    // enum callflags_t
};

struct vtableObj
{
    ea_t baseaddr;      // baseaddr reg in call [reg + off]
    ea_t largestOffset; // largest off seen in call [reg + off]
};
typedef struct vtableObj vtable_t;

typedef qvector<ulong> bphitlist_t;

struct dbgOptions
{
    netnode* calls;
    netnode* vtables;
    bphitlist_t* bplist;
    ulong options;
};

struct completedbp
{
    netnode* calls;
    bphitlist_t* callindex;
};
typedef completedbp completedbp_t;

enum uioptions_t
{
    DISPLAY_INCALLS = 0x0001,
    DISPLAY_BPS = 0x0002,
    DISPLAY_XS_BPS = 0x0004,
    MAKE_XREFS = 0x0008,
    MAKE_XS_XREFS = 0x0010,
    DISPLAY_VTABLES = 0x0020,
    INC_NONOFF_CALLS = 0x0040
};

enum callflags_t
{
    JMPSETFLAG = 1,
    XRSETFLAG = 2,
    XSEGFLAG = 4
};

char* regname [] =
{
    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"
};

enum REG
{
    eax,
    ecx,
    edx,
    ebx,
    esp,
    ebp,
    esi,
    edi,
    none = -1
};

enum EVENTS
{
    E_START,
    E_CANCEL,
    E_OPTIONS,
    E_HOOKFAIL,
    E_PROCFAIL,
    E_DWCALL,
    E_DWXREFS,
    E_DWVTABLE,
    E_PROCEXIT
};

// incomplete calls, choose2() list box
char icTitle [] = "Indirect calls";
static const char* icHeader [] =
{
    "Address", "Xref", "Function", "Instruction"
};

static const int icWidths [] =
{
    16, 4, 36, 20
};

// completed calls, choose2() list box
char ccTitle [] = "Completed calls";
static const char* ccHeader [] =
{
    "Address", "Function", "Xref", "Instruction", "Xseg", "Target", "Target Function"
};

static const int ccWidths [] =
{
    16, 28, 4, 18, 4, 16, 28
};

// vtables, choose2() list box
char vtTitle [] = "VTables";
static const char* vtHeader [] =
{
    "VTable ", "Largest offset seen", "Offset target", "Offset function", "Estimated size",
    "Estimated function count"
};

static const int vtWidths [] =
{
    16, 16, 16, 28, 16, 20
};

// ui string AskUsingForm_c()
const char preformat [] = "STARTITEM 0\n"
// Help
    "HELP\n"
    "This plugin searches for indirect calls. For example:\n"
    "\n"
    "call    dword ptr [eax+14h]\n"
    "jmp     eax\n"
    "\n"
    ""
    "Breakpoints are set on all the calls.\n"
    "A breakpoint  handler will:\n"
    "  1. Determine if one of its breakpoints triggered.\n"
    "  2. Delete the breakpoint\n"
    "  3. Step into the call\n"
    "  4. Record both the caller and callee addresses\n"
    "\n"
    "ENDHELP\n"

// Title
    "Indirect Call Plugin\n"
// Dialog Text
    "WARNING: Plugin executes the binary under the debugger.\n"
    "Ensure the process options have been set.\n\n"
    "Found %d indirect calls without xrefs\n\n"

//  Radio Buttons
    "<#Runs the debugger#"
    "Run Debugger:R>\n"
    "<#Collects data on indirect calls#"
    "Only collect information:R>>\n"

// Check Boxes
    "<# Create indirect call window. #"
    "Display indirect call list :C>\n"
    "<# Create BP window. #"
    "Display BPs hit :C>\n"
    "<# Include cross segment BPs in BP window. #"
    "Display cross segment BPs hit :C>\n"
    "<# Automatically create xrefs btwn caller and target. #"
    "Make the xrefs :C>\n"
    "<# Automatically create xrefs btwn caller and target in different segments. #"
    "Make the xrefs for cross segment calls:C>\n"
    "<# Create a vtable window #"
    "Display possible vtables :C>\n\n"
    "<# May lead to false positives (not recommended) #"
    "Include non-offset(call [eax]) calls for vtables  :C>>\n\n";

#endif /* INDIRECTCALLS_H_ */
