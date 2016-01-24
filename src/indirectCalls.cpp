/*********************************************************************
* Indirect Call IDA Pro plugin
*
* Copyright (c) 2008 Luis Miras
* Licensed under the BSD License
*
* Requirements: This plugin works alongside the IDA Pro debugger.
*               The plugin requires x86 processor. The plugin "should"
*               work under the IDA Linux debugger. It has not been
*               tested.
*
* Description: The plugin attempt to create cross references for
*              indirect calls/jmps. For brevity indirect calls/jmp
*              will be refered only as indirect calls. The plugin
*              also attempts to identify vtables.
*
* Strategy: The binary's current segment is scanned for indirect
*           calls. The binary is instrumented under the debugger.
*           A breakpoint handler either calculates the target or
*           steps into the target. Depending on user options cross
*           references will be made and possible vtables listed.
*
* Data structures: netnode and qvector are used. Both are built in IDA
*                  types, minimizing 3rd party dependencies. netnodes
*                  allow for persistent data,they are saved in the IDB
*                  However, in this plugin the netnodes are kill()'ed
*
* netnodes are implemented internally as B-trees.
* IDA uses netnodes extensively for its own storage.
* netnodes are defined in netnode.hpp.
*
* netnodes in the plugin: calls - holds all indirect calls
*                         vtable - holds all vtables
*
* netnodes have various internal data structures.
* The plugin uses 2 types of arrays:
*    altval -  a sparce array of 32 bit values, initially set to 0.
*    supval -  an array of variable sized objects (MAXSPECSIZE)
*
*  Addresses are used as keys into altval array. The value at the key
*  is then used as an index into the supval array. The supval array
*  holds an object of variable size.
*
*  This allows fast lookup using address keys, while being able to
*  iterate through all items using supval.
*
*  An example:
*
* .text:030CC0FB    call    dword ptr [eax+3Ch]
*
*  indirect_t myObj;
*  ulong index = calls->altval(0x030CC0FB);
*
*  if (index != 0) // indirect call (assume we assigned it earlier)
*  {
*    indirect_t myObj = calls->supval(index, &myObj, sizeof(myObj));
*    msg("%a -> %a\n", myObj.caller, myObj.target);
*  }
*
*  the calls netnode holds indirect_t objects
*  the vtables netnode holds vtable_t objects
*  bphitlist_t is a qvector that holds indexes into the calls netnode
*********************************************************************/

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>
//#include <allins.hpp>
#include <intel.hpp>
#include "indirectCalls.h"

dbgOptions gDbgOptions =
{
    NULL, NULL, NULL, 0
};

/*********************************************************************
* Function: vtEstimateSize
* Args:   ea_t addr    - base address of a VTable
* Return:   long         - Estimated VTable length
*
* This function attempts to calculate the size of a vtable given its
* base address. It checks xrefs to determine if still in a vtable
*
.text:03010D34  off_3010D34     dd offset sub_308A561
.text:03010D34
.text:03010D38                  dd offset sub_3082D8D
.text:03010D3C                  dd offset sub_3082DA6
.text:03010D40                  dd offset sub_3091542
.text:03010D44                  dd offset sub_30B9110
.text:03010D48                  dd 75667608h, 6174636Eh, 62h ;
                                                        ; 8 'vfunctab'
.text:03010D54  off_3010D54     dd offset sub_308A561
*
* Sometimes a string is stored at the end of a vtable as in this case.
* vtEstimateSize doesn't understand anything other than dword ptrs
 *********************************************************************/
long vtEstimateSize(ea_t addr)
{
    flags_t flags;
    ea_t curraddr = addr;
    ea_t lastaddr = addr;
    bool done = false;

    curraddr = next_head(lastaddr, BADADDR);

    while (!done)
    {
        if (curraddr - lastaddr != 4) // DWORD size differences
        {
            done = true;
        }
        flags = getFlags(curraddr);

        if (!done && !isDwrd(flags))
        {
            done = true;
        }

        // a dref_to could suggest the start of a new vtable
        if (!done && get_first_dref_to(curraddr) != BADADDR)
            done = true;

        if (!done)
        {
            lastaddr = curraddr;
            curraddr = next_head(lastaddr, BADADDR);
        }
    }
    return lastaddr - addr + 4;
}


/*********************************************************************
* Function: vtDescription
*
* This is a standard callback in the choose2() SDK call. This function
* fills in all column content for a specific line. Headers names are
* set during the first call to this function, when n == 0.
* arrptr is a char* array to the column content for a line.
*                 arrptr[number of columns]
*
* vtDescription creates 6 columns based on the vtHeader array
*********************************************************************/
void idaapi vtDescription(void* obj, ulong n, char*const * arrptr)
{
    netnode* node = (netnode* )obj;
    vtable_t curr_vtable;
    ea_t target;
    long vtSize;

    if (n == 0) // sets up headers
    {
        for ( int i = 0; i < qnumber(vtHeader); i++ )
            qstrncpy(arrptr[i], vtHeader[i], MAXSTR);
        return;
    }

	// Empty netnode
    if (!getobjcount(node))
        return;

    qstring buffer;
    node->supval(n, &curr_vtable, sizeof(curr_vtable));
    vtSize = vtEstimateSize(curr_vtable.baseaddr);
    target = get_long(curr_vtable.largestOffset + curr_vtable.baseaddr);

    get_nice_colored_name(curr_vtable.baseaddr, arrptr[0], MAXSTR, CNAMEOPT);
    qsnprintf(arrptr[1], MAXSTR, "%04a", curr_vtable.largestOffset);
    get_nice_colored_name(target, arrptr[2], MAXSTR, CNAMEOPT);

    buffer = get_short_name(target); //demangles fname
    qsnprintf(arrptr[3], MAXSTR, "%s", buffer);
    qsnprintf(arrptr[4], MAXSTR, "%04a", vtSize);
    qsnprintf(arrptr[5], MAXSTR, "%04a", vtSize / 4);

    return;
}


/*********************************************************************
* Function: vtEnter
*
* This is a standard callback in the choose2() SDK call. This function
* is called when the user pressed Enter or Double-Clicks on a line in
* the chooser list.
*********************************************************************/
void idaapi vtEnter(void* obj, ulong n)
{
    vtable_t curr_vtable;
    netnode* node = (netnode* )obj;

    node->supval(n, &curr_vtable, sizeof(curr_vtable));
    jumpto(curr_vtable.baseaddr);
    return;
}


/*********************************************************************
* Function: vtDestroy
*
* This is a standard callback in the choose2() SDK call. This function
* is called when the chooser list is being destroyed. Resource cleanup
* is common in this function. In this case any resource
* cleanup is handled by register_event().
*********************************************************************/
void idaapi vtDestroy(void* obj)
{
    netnode* node = (netnode* )obj;
    msg("\"%s\" window closed\n", vtTitle);
    register_event(E_DWVTABLE);
    return;
}


/*********************************************************************
* Function: createVTableWindow
*
* A wrapper around choose2() API. 'Generic list chooser (n-column)'
* This sets up the callbacks and necessary options.
* NOTE: 1. Cannot free the "object to show" until chooser closes
*       2. Cannot unload plugin until chooser closes,
*          removing callbacks.
*********************************************************************/
void createVTableWindow(netnode* vtables)
{
    choose2(false,     // non-modal window
    -1, -1, -1, -1,    // position is determined by Windows
    vtables,           // object to show
    qnumber(vtHeader), // number of columns
    vtWidths,          // widths of columns
    size,              // function that returns number of lines
    vtDescription,     // function that generates a line
    vtTitle,           // window title
    -1,                // use the default icon for the window
    0,                 // position the cursor on the first line
    NULL,              // "kill" callback
    NULL,              // "new" callback
    NULL,              // "update" callback
    NULL,              // "edit" callback
    vtEnter,           // function to call when the user pressed Enter
    vtDestroy,         // function to call when the window is closed
    NULL,              // use default popup menu items
    NULL);             // use the same icon for all line
}


/*********************************************************************
* Function: icDescription
*
* This is a standard callback in the choose2() SDK call. This function
* fills in all column content for a specific line. Headers names are
* set during the first call to this function, when n == 0.
* arrptr is a char* array to the column content for a line.
*                 arrptr[number of columns]
*
* vtDescription creates 4 columns based on the icHeader array
*********************************************************************/
void idaapi icDescription(void* obj, ulong n, char*const * arrptr)
{
    netnode* node = (netnode* )obj;
    indirect_t curr_indirect;

    if (n == 0) // sets up headers
    {
        for ( int i = 0; i < qnumber(icHeader); i++ )
            qstrncpy(arrptr[i], icHeader[i], MAXSTR);
        return;
    }

    // list empty?
    if (!getobjcount(node))
        return;

    qstring buffer;

    node->supval(n, &curr_indirect, sizeof(curr_indirect));
    func_t* currFunc = get_func(curr_indirect.caller);

    decode_insn(curr_indirect.caller);

    get_nice_colored_name(curr_indirect.caller, arrptr[0], MAXSTR, CNAMEOPT); // address

    if (curr_indirect.flags & XRSETFLAG)
        qstrncpy(arrptr[1], "x", MAXSTR);
    else
        qstrncpy(arrptr[1], "-", MAXSTR);

    buffer = get_short_name(currFunc->startEA);
    qsnprintf(arrptr[2], MAXSTR, "%s", buffer);

	char *buffer2 = (char *)buffer.c_str();
	generate_disasm_line(cmd.ea, buffer2, sizeof(buffer2));
    tag_remove(buffer2, buffer2, sizeof(buffer2));
    qsnprintf(arrptr[3], MAXSTR, "%s", buffer2);

    return;
}


/*********************************************************************
* Function: icEnter
*
* This is a standard callback in the choose2() SDK call. This function
* is called when the user pressed Enter or Double-Clicks on a line in
* the chooser list.
*********************************************************************/
void idaapi icEnter(void* obj, ulong n)
{
    indirect_t curr_indirect;
    netnode* node = (netnode* )obj;

    node->supval(n, &curr_indirect, sizeof(curr_indirect));
    jumpto(curr_indirect.caller);
    return;
}


/*********************************************************************
* Function: icDestroy
*
* This is a standard callback in the choose2() SDK call. This function
* is called when the chooser list is being destroyed. Resource cleanup
* is common in this function. In this case any resource cleanup is
* handled by register_event().
*********************************************************************/
void idaapi icDestroy(void* obj)
{
    netnode* node = (netnode* )obj;
    msg("\"%s\" window closed\n", icTitle);
    register_event(E_DWCALL);
    return;
}


/*********************************************************************
* Function: size
*
* This is a standard callback in the choose2() SDK call. This function
* returns the number of lines to be used in the chooser list.
*********************************************************************/
ulong idaapi size(void* obj)
{
    netnode* node = (netnode* )obj;
    return getobjcount(node);
}


/*********************************************************************
* Function: createIndirectCallWindow
*
* A wrapper around choose2() API. 'Generic list chooser (n-column)'
* This sets up the callbacks and necessary options.
* NOTE: 1. Cannot free the "object to show" until chooser closes
*       2. Cannot unload plugin until chooser closes,
*          removing callbacks.
*********************************************************************/
void createIndirectCallWindow(netnode* calls)
{
    choose2(false,     // non-modal window
    -1, -1, -1, -1,    // position is determined by Windows
    calls,             // object to show
    qnumber(icHeader), // number of columns
    icWidths,          // widths of columns
    size,              // function that returns number of lines
    icDescription,     // function that generates a line
    icTitle,           // window title
    -1,                // use the default icon for the window
    0,                 // position the cursor on the first line
    NULL,              // "kill" callback
    NULL,              // "new" callback
    NULL,              // "update" callback
    NULL,              // "edit" callback
    icEnter,           // function to call when the user pressed Enter
    icDestroy,         // function to call when the window is closed
    NULL,              // use default popup menu items
    NULL);             // use the same icon for all line
}


/*********************************************************************
* Function: ccDescription
*
* This is a standard callback in the choose2() SDK call. This function
* fills in all column content for a specific line. Headers names are
* set during the first call to this function, when n == 0.
* arg:   arrptr is a char* array to the column content for a line.
*        arrptr[number of columns]
* arg: completedbp_t* is atruct: netnode*    - points to all calls
*                                bphitlist_t - indexes of hit calls
*
* ccDescription creates 7 columns based on the icHeader array
*********************************************************************/
void idaapi ccDescription(void* obj, ulong n, char*const * arrptr)
{
    completedbp_t* cbp = (completedbp_t* )obj;
    indirect_t curr_indirect;

    if (n == 0) // sets up headers
    {
        for ( int i = 0; i < qnumber(ccHeader); i++ )
            qstrncpy(arrptr[i], ccHeader[i], MAXSTR);
        return;
    }

    bphitlist_t& tmp = *(bphitlist_t* )cbp->callindex;
    ulong index = tmp[n - 1];

    if (!tmp.size()) // only needed if choose2 kill callback used
        return;      // since it removes members

    qstring buffer;

    cbp->calls->supval(index, &curr_indirect, sizeof(curr_indirect));
    func_t* currFunc = get_func(curr_indirect.caller);
    decode_insn(curr_indirect.caller); //

    // seg.addr
    get_nice_colored_name(curr_indirect.caller, arrptr[0], MAXSTR, CNAMEOPT);

    buffer = get_short_name(currFunc->startEA);
    qsnprintf(arrptr[1], MAXSTR, "%s", buffer);

    if (curr_indirect.flags & XRSETFLAG)
        qstrncpy(arrptr[2], "x", MAXSTR); // made a cross reference
    else
        qstrncpy(arrptr[2], "-", MAXSTR);

	char *buffer2 = (char *)buffer.c_str();
    // get instruction disasm, remove color info
    generate_disasm_line(cmd.ea, buffer2, sizeof(buffer2));
    tag_remove(buffer2, buffer2, sizeof(buffer2));
    qsnprintf(arrptr[3], MAXSTR, "%s", buffer2);

    if (curr_indirect.flags & XSEGFLAG)
        qstrncpy(arrptr[4], "x", MAXSTR); // cross segment reference
    else
        qstrncpy(arrptr[4], "-", MAXSTR);

    get_nice_colored_name(curr_indirect.target, arrptr[5], MAXSTR, CNAMEOPT);

    currFunc = get_func(curr_indirect.target);
    //demangles fname
    buffer = get_short_name(currFunc->startEA);
    qsnprintf(arrptr[6], MAXSTR, "%s", buffer);

    return;
}


/*********************************************************************
* Function: ccEnter
*
* This is a standard callback in the choose2() SDK call. This function
* is called when the user pressed Enter or Double-Clicks on a line in
* the chooser list.
*********************************************************************/
void idaapi ccEnter(void* obj, ulong n)
{
    completedbp_t* cbp = (completedbp_t* )obj;
    bphitlist_t& tmp = *(bphitlist_t* )cbp->callindex;
    indirect_t curr_indirect;
    ulong index = tmp[n - 1];

    cbp->calls->supval(index, &curr_indirect, sizeof(curr_indirect));
    jumpto(curr_indirect.caller);
    return;
}


/*********************************************************************
* Function: ccDestroy
*
* This is a standard callback in the choose2() SDK call. This function
* is called when the chooser list is being destroyed. Resource cleanup
* is common in this function. In this case any resource cleanup is
* handled by register_event().
*********************************************************************/
void idaapi ccDestroy(void* obj)
{
    completedbp_t* cbp = (completedbp_t* )obj;
    msg("\"%s\" window closed\n", ccTitle);
    register_event(E_DWXREFS);
    return;
}


/*********************************************************************
* Function: ccSize
*
* This is a standard callback in the choose2() SDK call. This function
* returns the number of lines to be used in the chooser list.
*********************************************************************/
ulong idaapi ccSize(void* obj)
{
    completedbp_t* cbp = (completedbp_t* )obj;
    return cbp->callindex->size();
}


/*********************************************************************
* Function: createCompletedBpWindow
*
* A wrapper around choose2() API. 'Generic list chooser (n-column)'
* This sets up the callbacks and necessary options.
* NOTE: 1. Cannot free the "object to show" until chooser closes
*       2. Cannot unload plugin until chooser closes,
*          removing callbacks.
*********************************************************************/
void createCompletedBpWindow(netnode* calls, bphitlist_t* bplist)
{
    completedbp_t* bp = new completedbp_t;
    bp->calls = calls;
    bp->callindex = bplist;

    choose2(false,     // non-modal window
    -1, -1, -1, -1,    // position is determined by Windows
    bp,                // object to show
    qnumber(ccHeader), // number of columns
    ccWidths,          // widths of columns
    ccSize,            // function that returns number of lines
    ccDescription,     // function that generates a line
    ccTitle,           // window title
    -1,                // use the default icon for the window
    0,                 // position the cursor on the first line
    NULL,              // "kill" callback
    NULL,              // "new" callback
    NULL,              // "update" callback
    NULL,              // "edit" callback
    ccEnter,           // function to call when the user pressed Enter
    ccDestroy,         // function to call when the window is closed
    NULL,              // use default popup menu items
    NULL);             // use the same icon for all line
}


/*********************************************************************
* Function: requestSetBps
*
* requests all our breakpoints be set, then run_requests
*********************************************************************/
void requestSetBps(netnode* node)
{
    indirect_t my_indirect;

    long no_calls = getnodesize(node);
    msg("requestSetBps  size: %x\n", no_calls);

    for ( int i = 1; i < no_calls; ++i )
    {
        node->supval(i, &my_indirect, sizeof(my_indirect));
        request_add_bpt(my_indirect.caller);
    }
    run_requests();
    return;
}


/*********************************************************************
 * Function: requestDelBps
 *
 * requests all our breakpoints be deleted, caller calls run_requests
 *********************************************************************/
void requestDelBps(netnode* node)
{
    indirect_t my_indirect;

    long no_calls = getnodesize(node);
    msg("requestDelBps  size: %x\n", no_calls);

    for ( int i = 1; i < no_calls; ++i )
    {
        node->supval(i, &my_indirect, sizeof(my_indirect));
        request_del_bpt(my_indirect.caller);
    }
    return;
}


/*********************************************************************
 * Function: setBps
 *
 * set all our breakpoints
 *********************************************************************/
void setBps(netnode* node)
{
    indirect_t my_indirect;

    long no_calls = getnodesize(node);
    msg("setBps  size: %x\n", no_calls);

    for ( int i = 1; i < no_calls; ++i )
    {
        node->supval(i, &my_indirect, sizeof(my_indirect));
        add_bpt(my_indirect.caller);
    }
    return;
}


/*********************************************************************
* Function: delBps
*
* delete all our breakpoints
*********************************************************************/
void delBps(netnode* node)
{
    indirect_t my_indirect;

    long no_calls = getnodesize(node);
    msg("delBps  size: %x\n", no_calls);

    for ( int i = 1; i < no_calls; ++i )
    {
        node->supval(i, &my_indirect, sizeof(my_indirect));
        del_bpt(my_indirect.caller);
    }
    return;
}


/*********************************************************************
* Function: setTargetXref
*
* This function serves two purposes. First decides whether to add the
* call to the completed call/bp list. It also can create the cross
* reference between the caller and the target.
*********************************************************************/
void setTargetXref(dbgOptions* myDbg, long index, indirect_t* myIndirect)
{
    bphitlist_t* entry = myDbg->bplist;
    ulong options = myDbg->options;
    ea_t from = myIndirect->caller;
    ea_t to = myIndirect->target;
    short& flags = myIndirect->flags;
    segment_t* from_seg = getseg(from);
    segment_t* to_seg = getseg(to);

    if (from_seg == to_seg)
    {
        if (options & MAKE_XREFS)
        {
            flags |= XRSETFLAG;

            if (flags & JMPSETFLAG)
                add_cref(from, to, (cref_t)(fl_JN | XREF_USER));
            else
                add_cref(from, to, (cref_t)(fl_CN | XREF_USER));
        }
        entry->push_back(index);
    }
    else // cross segment
    {
        if (to_seg != NULL && !(to_seg->is_ephemeral_segm()))
        {
            flags |= XSEGFLAG;

            if (options & MAKE_XS_XREFS)
            {
                flags |= XRSETFLAG;

                if (flags & JMPSETFLAG)
                    add_cref(from, to, (cref_t)(fl_JF | XREF_USER));
                else
                    add_cref(from, to, (cref_t)(fl_CF | XREF_USER));
            }

            if (options & DISPLAY_XS_BPS)
            {
                entry->push_back(index);
            }
        }
    }
}


/*********************************************************************
* Function: addVTable
*
* Determines if vtable is considered valid. A new vtable is added to
* the vtable netnode. If the vtable already exists. The offset is
* checked against the largest offset recorded for the vtable.
*********************************************************************/
void addVTable(dbgOptions* myDbg, ea_t vtaddr, indirect_t* myIndirect)
{
    ea_t from = myIndirect->caller;
    ea_t to = myIndirect->target;
    ea_t offset = myIndirect->offset;

    segment_t* from_seg = getseg(from);
    segment_t* vt_seg = getseg(vtaddr);
    netnode* vtables = myDbg->vtables;
    ulong options = myDbg->options;

    if (offset || (options& INC_NONOFF_CALLS))
    {
        if (from_seg != vt_seg) // only documenting vtables in from_seg
        {
            return;
        }

        if ((get_first_dref_to(vtaddr) == BADADDR) || (get_first_dref_from(vtaddr) == BADADDR))
        {
            msg("%x to %x , probably jump table, not vtable [%x]\n", from, to, vtaddr);
        }
        else // considered a valid vtable
        {
            ulong tmp = vtables->altval(vtaddr);

            if (tmp == 0) // new vtable
            {
                vtable_t my_vtable;
                int vtable_counter = getnodesize(vtables);
                my_vtable.baseaddr = vtaddr;
                my_vtable.largestOffset = myIndirect->offset;
                vtables->altset(vtaddr, vtable_counter);
                vtables->supset(vtable_counter++, &my_vtable, sizeof(my_vtable));
                setnodesize(vtables, vtable_counter);
                msg("%x NEW VTABLE caller: %x , to: %x\n", vtaddr, from, to);
            }
            else // vtable already defined
            {
                vtable_t tmpVtable;
                vtables->supval(tmp, &tmpVtable, sizeof(tmpVtable));

                // new offset > old offset
                if (myIndirect->offset > tmpVtable.largestOffset)
                {
                    tmpVtable.largestOffset = myIndirect->offset;
                    vtables->supset(tmp, &tmpVtable, sizeof(tmpVtable));
                }
            }
        }
    }
}


/*********************************************************************
* Function: callback
*
* The debugger calls this function when handling any HT_DBG events.
* The dbgOptions structure is passed to this function allowing the use
* of previously defined data structures and user options.
*
* callback handles 3 types of HT_DBG events
*
* dbg_bpt - All breakpoints are handled here. The bp address
*           is checked to be ours. If not the the process is
*           suspended. Otherwise:
*           The instruction is call [eax] with or without an
*           offset OR anything else.
*
*           For everything else 'step into' is requested.
*           The current bp addresses is saved in last_bp
*           for the step_into handler
*
*           With the instruction decoded, both the base and
*           target can be calculated.
*           addVTable() & setTargetXref() process if
*           vtables and cross references are made. The
*           indirect_t obj is saved with updates.
*           continue_process() is called
*
* dbg_step_into  - All step_into events are handled here. last_bp
*           is checked. For user caused step_into event
*           suspend_process() is called.
*           setTargetXref() deltemines if cross references
*           are made. The indirect_t obj is saved with updates.
*           continue_process() is called
*
* dbg_process_exit  - This event signifies that the debugger is
*           shutting down. Brealpoints are cleared and depending on
*           options, up to three chooser list windows are opened.
*********************************************************************/
int idaapi callback(void* user_data, int notification_code, va_list va)
{
    dbgOptions* my_dbg = (dbgOptions* )user_data;
    netnode* calls = my_dbg->calls;
    ulong options = my_dbg->options;
    static ea_t last_bp = BADADDR;
    ea_t from = BADADDR;
    ea_t vtaddr = BADADDR;
    ea_t to = BADADDR;
    regval_t regval;

    switch (notification_code)
    {
        case dbg_bpt:
        {
            va_arg(va, tid_t);
            from = va_arg(va, ea_t);
            long index = calls->altval(from);

            if (index == 0)
            {
                // not one of our breakpoints
                msg("user dbg_bpt, not set by plugin\n");
                suspend_process();
                return 0;
            }

            indirect_t my_indirect;
            calls->supval(index, &my_indirect, sizeof(my_indirect));

            // check for call [reg] or call [reg + offset]
            if (my_indirect.call_reg == none)
            {
                last_bp = from;
                request_del_bpt(from);
                request_step_into();
                run_requests();
                break;
            }

            get_reg_val(regname[my_indirect.call_reg], &regval);
            vtaddr = (ea_t)regval.ival;

            // flushes possibly stale memory cache
            invalidate_dbgmem_contents((ea_t)regval.ival, 0x100 + my_indirect.offset);
            to = get_long(my_indirect.offset + vtaddr);
            my_indirect.target = to;

            addVTable(my_dbg, vtaddr, &my_indirect);
            setTargetXref(my_dbg, index, &my_indirect);
            // save completed indirect
            calls->supset(index, &my_indirect, sizeof(my_indirect));

            del_bpt(from);
            continue_process();
            break;
        }
        case dbg_step_into:
        {
            from = last_bp;

            if (from == BADADDR)
            {
                msg("user dbg_step_into, not set by plugin\n");
                suspend_process();
                return 0;
            }

            long index = calls->altval(from);
            get_reg_val("EIP", &regval);
            to = (ea_t)regval.ival;

            indirect_t my_indirect;
            calls->supval(index, &my_indirect, sizeof(my_indirect));
            my_indirect.target = to;

            setTargetXref(my_dbg, index, &my_indirect);
            // save completed indirect
            calls->supset(index, &my_indirect, sizeof(my_indirect));

            last_bp = BADADDR;
            continue_process();
            break;
        }
        case dbg_process_exit:
        {
            unhook_from_notification_point(HT_DBG, callback, user_data);
            requestDelBps(calls);
            run_requests();
            register_event(E_PROCEXIT);

            if (options & DISPLAY_INCALLS)
            {
                createIndirectCallWindow(calls);
            }

            if (options & DISPLAY_BPS)
            {
                createCompletedBpWindow(calls, my_dbg->bplist);
            }

            if (options & DISPLAY_VTABLES)
            {
                createVTableWindow(my_dbg->vtables);
            }
            break;
        }
        default:
            break;
    }
    return 0;
}


/*********************************************************************
* Function: getnodesize
*
* returns size (including location 0)
*********************************************************************/
long getnodesize(netnode* node)
{
    return node->altval(NODE_COUNT);
}


/*********************************************************************
* Function: getobjcount
*
* returns number of items in the netnode not counting invalid slot 0
* see data structure documentation at top of file
*********************************************************************/
long getobjcount(netnode* node)
{
    return node->altval(NODE_COUNT) - 1;
}


/*********************************************************************
* Function: setnodesize
*
* store netnode size
*********************************************************************/
bool setnodesize(netnode* node, long size)
{
    return node->altset(NODE_COUNT, size);
}


/*********************************************************************
* Function: fillIndirectObj
*
* Determines if instruction is call [reg+offset], call [reg], or other
* Fills in the indirect_t struct.
*********************************************************************/
void fillIndirectObj(indirect_t& currcall)
{
    currcall.caller = cmd.ea;
    currcall.target = BADADDR;
    currcall.call_reg = none;
    currcall.offset = 0;

    if (cmd.itype == NN_callni)
    {
        // need a single opcode
        ushort no_operands = 0;

        while (no_operands < UA_MAXOP && cmd.Operands[no_operands].type != o_void)
        {
            no_operands++;
        }

        if (no_operands == 1)
        {
            if (cmd.Operands[0].type == o_phrase)
            {
                currcall.call_reg = cmd.Operands[0].reg;
            }
            else if (cmd.Operands[0].type == o_displ)
            {
                currcall.call_reg = cmd.Operands[0].reg;
                currcall.offset = cmd.Operands[0].addr;
            }
        }
    }
    else if (cmd.itype & NNJMPxI) // jmp?
    {
        currcall.flags |= JMPSETFLAG;
    }
}


/*********************************************************************
* Function: findIndirectCalls
*
* This function through a segment for indirect calls and jmps
* NN_callfi, NN_callni, NN_jmpfi, NN_jmpni
* then it pkgs it in a inidirect_t struct and stores in the netnode
*********************************************************************/
void findIndirectCalls(segment_t* seg, netnode* node)
{
    ea_t addr = seg->startEA;
    ulong counter = getnodesize(node);

    while ((addr < seg->endEA) && (addr != BADADDR))
    {
        flags_t flags = getFlags(addr);

        if (isHead(flags) && isCode(flags))
        {
            if (decode_insn(addr) != 0)
            {
                switch (cmd.itype)
                {
                    case NN_callfi:
                    case NN_callni:
                    case NN_jmpfi:
                    case NN_jmpni:
                    {
                        if (get_first_fcref_from(cmd.ea) == BADADDR
                            && get_first_dref_from(cmd.ea) == BADADDR) //no fwd xref
                        {
                            indirect_t currcall;
                            fillIndirectObj(currcall);
                            node->altset(cmd.ea, counter); // altval keyed by addr
                            node->supset(counter++, &currcall, sizeof(currcall));
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
        }
        addr = next_head(addr, seg->endEA);
    }
    setnodesize(node, counter);
    return;
}


void closeListWindows(void)
{
    close_chooser(icTitle);
    close_chooser(ccTitle);
    close_chooser(vtTitle);
}


/*********************************************************************
* Function: register_event
*
* This function serves as an interface to three semaphores in the form
* of event messages. IDA Pro is single threaded and is non reentrant.
* True concurrency requirements such as mutexes and atomic operations
* are not needed.
*
* The caller reports an event and this function adjusts the semaphores
* and can release resources when needed.
* semaphores are tied to the
*       netnode*     calls   - all indirect calls
*       netnode*     vtables - all vtables
*       bphitlist_t* bplist  - bp hits, an index list into
*                                       netnode* call
*********************************************************************/
void register_event(ulong rEvent)
{
    static long dbgState = 0;
    static long semcall = 0;
    static long semxref = 0;
    static long semvtable = 0;

    switch (rEvent)
    {
        case E_START:
        {
            closeListWindows();

            if (gDbgOptions.calls)
            {
                gDbgOptions.calls->kill();
            }

            if (gDbgOptions.vtables)
            {
                gDbgOptions.vtables->kill();
            }

            if (gDbgOptions.bplist)
            {
                gDbgOptions.bplist->~qvector();
            }
            semcall = semxref = dbgState = semvtable = 0;
            break;
        }
        case E_CANCEL:
        {
            semcall = semxref = dbgState = semvtable = 0;
            gDbgOptions.calls->kill();
            gDbgOptions.vtables->kill();
            gDbgOptions.bplist->~qvector();
            break;
        }
        case E_OPTIONS:
        {
            if ((~gDbgOptions.options) >> 15)
            {
                dbgState++;
                semcall++;
                semxref++;
                semvtable++;
            }

            if (gDbgOptions.options & DISPLAY_INCALLS)
            {
                semcall++;
            }

            if (((gDbgOptions.options& DISPLAY_BPS) >> 1) && dbgState)
            {
                semcall++;
                semxref++;
            }

            if (((gDbgOptions.options& DISPLAY_VTABLES) >> 5) && dbgState)
            {
                semvtable++;
            }
            break;
        }
        case E_HOOKFAIL:
        {
            dbgState = semvtable = semxref = 0;
            break;
        }
        case E_PROCFAIL:
        {
            // note: call window may be open
            delBps(gDbgOptions.calls);
            semcall--;
            dbgState = semvtable = semxref = 0;
            unhook_from_notification_point(HT_DBG, callback, &gDbgOptions);
            break;
        }
        case E_DWCALL:
        {
            semcall--;

            if (!semcall)
            {
                gDbgOptions.calls->kill();
            }
            break;
        }
        case E_DWXREFS:
        {
            semxref--;
            semcall--;

            if (!semcall)
            {
                gDbgOptions.calls->kill();
            }

            if (!semxref)
            {
                gDbgOptions.bplist->~qvector();
            }
            break;
        }
        case E_DWVTABLE:
        {
            semvtable--;

            if (!semvtable)
            {
                gDbgOptions.vtables->kill();
            }
            break;
        }
        case E_PROCEXIT:
        {
            dbgState = 0;
            semcall--;
            semvtable--;
            semxref--;

            if (!semxref)
            {
                gDbgOptions.bplist->~qvector();
            }

            if (!semcall)
            {
                gDbgOptions.calls->kill();
            }

            if (!semvtable)
            {
                gDbgOptions.vtables->kill();
            }
            break;
        }
        default:
        {
            msg("ERROR UNKNOWN EVENT\n");
            msg("%s dbg:%d scall:%d sxref:%d svtable:%d \n", "ERROR", dbgState, semcall, semxref, semvtable);
            break;
        }
    }
}


/*********************************************************************
* Function: run
*
* run is a plugin_t function. It is executed when the plugin is run.
* This function brings up the UI, collects data and sets the debugger
* callback.
*   arg - defaults to 0. It can be set by a plugins.cfg entry. In this
*         case the arg is used for debugging/development purposes
* ;plugin displayed name    filename        hotkey  arg
* indirectCalls_dbg         indirectCalls   Alt-F8  0
* indirectCalls_unload      indirectCalls   Alt-F9  415
*
* Thus Alt-F9 runs the plugin with an option that will unload it.
* This allows (edit/recompile/copy) cycles.
*********************************************************************/
void run(int arg)
{
    char nodename_calls [] = "$ indirect calls";
    char nodename_vtables [] = "$ vtables";
    ea_t curraddr = get_screen_ea();
    segment_t* my_seg = getseg(curraddr);
    char* format;
    short checkbox = DISPLAY_INCALLS | DISPLAY_BPS | DISPLAY_VTABLES;
    short radiobutton = 0;
    int start_status;

    register_event(E_START);

    if (arg == 415)
    {
        PLUGIN.flags |= PLUGIN_UNL;
        msg("Unloading plugin...\n");
        return;
    }

    netnode* calls = new netnode;
    netnode* vtables = new netnode;
    bphitlist_t* hitlist = new bphitlist_t;

    if (calls->create(nodename_calls) == 0)
    {
        calls->kill();
        msg("ERROR: creating netnode %s\n", nodename_calls);
        return;
    }

    if (vtables->create(nodename_vtables) == 0)
    {
        msg("ERROR: creating netnode %s\n", nodename_vtables);
        calls->kill();
        vtables->kill();
        return;
    }
    calls->altset(NODE_COUNT, 1);     // position 0 is not used
    vtables->altset(NODE_COUNT, 1);   // position 0 is not used

    findIndirectCalls(my_seg, calls); // finds jmps/calls

    ulong format_size = sizeof(preformat) + 9;
    format = (char* )qalloc(format_size);
    qsnprintf(format, format_size, preformat, getobjcount(calls));

    int ok = AskUsingForm_c(format, &radiobutton, &checkbox); // UI

    gDbgOptions.calls = calls;
    gDbgOptions.vtables = vtables;
    gDbgOptions.bplist = hitlist;
    gDbgOptions.options = checkbox;

    register_event(E_OPTIONS);

    if (!ok)
    {
        msg("user canceled,  exiting, unloading\n");
        register_event(E_CANCEL);
        PLUGIN.flags |= PLUGIN_UNL;
        return;
    }

    // debugger closing this window, now only open for non debugger
    if ((checkbox& DISPLAY_INCALLS) && (radiobutton == 1))
    {
        createIndirectCallWindow(calls);
    }

    if (radiobutton == 1)
        return; // only collect data

    // the hook is created here. callback() will receive HT_DBG
    // events only. gDbgOptions is passed to callback()
    // it is global so termination funcs have access
    if (!hook_to_notification_point(HT_DBG, callback, &gDbgOptions))
    {
        warning("Could not hook to notification point\n");
        register_event(E_HOOKFAIL);
        return;
    }

    requestSetBps(calls);
    start_status = start_process(NULL, NULL, NULL);

    if (start_status == 1) // SUCCESS
    {
        msg("process started ...\n");
        return;
    }
    else if (start_status == -1)
    {
        warning("Sorry, could not start the process");
    }
    else
    {
        msg("Process start canceled by user\n");
    }
    register_event(E_PROCFAIL);
    return;
}


/*********************************************************************
* Function: init
*
* init is a plugin_t function. It is executed when the plugin is
* initially loaded by IDA
*********************************************************************/
int init(void)
{
    if (ph.id != PLFM_386) // intel x86
        return PLUGIN_SKIP;
    return PLUGIN_OK;
}


/*********************************************************************
* Function: term
*
* term is a plugin_t function. It is executed when the plugin is
* unloading. Typically cleanup code is executed here.
* The unhook is called as a safety precaution.
* The windows are closed to remove the choose2() callbacks
*********************************************************************/
void term(void)
{
    unhook_from_notification_point(HT_DBG, callback, &gDbgOptions);
    closeListWindows();
    return;
}

char comment [] = "indirectCalls ";
char help [] = "This plugin looks\nfor indirect\ncalls\n";
char wanted_name [] = "indirectCalls";
char wanted_hotkey [] = "Alt-F7";

/* defines the plugins interface to IDA */
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION, 0, // plugin flags
    init,                     // initialize
    term,                     // terminate. this pointer may be NULL.
    run,                      // invoke plugin
    comment,                  // comment about the plugin
    help,                     // multiline help about the plugin
    wanted_name,              // the preferred short name of the plugin
    wanted_hotkey             // the preferred hotkey to run the plugin
};
