#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "aes.h"

#pragma prefast(disable \
                : __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES 0x00000001
#define PTDBG_TRACE_OPERATION_STATUS 0x00000002

ULONG gTraceFlags = 0;

#define PT_DBG_PRINT(_dbgLevel, _string) \
    (FlagOn(gTraceFlags, (_dbgLevel)) ? DbgPrint _string : ((int)0))

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath);

NTSTATUS
PtInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

VOID PtInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

VOID PtInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

NTSTATUS
PtUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS
PtInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

VOID PtOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext);

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

BOOLEAN
PtDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, PtUnload)
#pragma alloc_text(PAGE, PtInstanceQueryTeardown)
#pragma alloc_text(PAGE, PtInstanceSetup)
#pragma alloc_text(PAGE, PtInstanceTeardownStart)
#pragma alloc_text(PAGE, PtInstanceTeardownComplete)
#endif

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_READ,
     0,
     PtPreOperationPassThrough,
     PtPostOperationPassThrough},

    {IRP_MJ_WRITE,
     0,
     PtPreOperationPassThrough,
     PtPostOperationPassThrough},

    {IRP_MJ_OPERATION_END}};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION), //  Size
    FLT_REGISTRATION_VERSION, //  Version
    0,                        //  Flags

    NULL,      //  Context
    Callbacks, //  Operation callbacks

    PtUnload, //  MiniFilterUnload

    PtInstanceSetup,            //  InstanceSetup
    PtInstanceQueryTeardown,    //  InstanceQueryTeardown
    PtInstanceTeardownStart,    //  InstanceTeardownStart
    PtInstanceTeardownComplete, //  InstanceTeardownComplete

    NULL, //  GenerateFileName
    NULL, //  GenerateDestinationFileName
    NULL  //  NormalizeNameComponent

};

NTSTATUS
PtInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)

{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("PassThrough!PtInstanceSetup: Entered\n"));

    return STATUS_SUCCESS;
}

NTSTATUS
PtInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)

{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("PassThrough!PtInstanceQueryTeardown: Entered\n"));

    return STATUS_SUCCESS;
}

VOID PtInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)

{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("PassThrough!PtInstanceTeardownStart: Entered\n"));
}

VOID PtInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)

{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("PassThrough!PtInstanceTeardownComplete: Entered\n"));
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)

{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("PassThrough!DriverEntry: Entered\n"));

    status = FltRegisterFilter(DriverObject,
                               &FilterRegistration,
                               &gFilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status))
    {
        status = FltStartFiltering(gFilterHandle);

        if (!NT_SUCCESS(status))
        {
            FltUnregisterFilter(gFilterHandle);
        }
    }

    return status;
}

NTSTATUS
PtUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags)

{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("PassThrough!PtUnload: Entered\n"));

    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)

{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PassThrough!PtPreOperationPassThrough: Entered\n"));

    if (PtDoRequestOperationStatus(Data))
    {

        status = FltRequestOperationStatusCallback(Data,
                                                   PtOperationStatusCallback,
                                                   (PVOID)(++OperationStatusCtx));
        if (!NT_SUCCESS(status))
        {

            PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
                         ("PassThrough!PtPreOperationPassThrough: FltRequestOperationStatusCallback Failed, status=%08x\n",
                          status));
        }
    }

    // DbgPrint("Driver-Filter, filename %wZ ", Data->Iopb->TargetFileObject->FileName.Buffer); //  Вывод имени файла (FileName в UNICODE_STRING)
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED |
            FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo);

    UNICODE_STRING RecuiredFileExtension = RTL_CONSTANT_STRING(L"testlabextension"); // Перевод расширения в UNICODE_STRING

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

VOID PtOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext)

{
    UNREFERENCED_PARAMETER(FltObjects);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("PassThrough!PtOperationStatusCallback: Entered\n"));

    PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
                 ("PassThrough!PtOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                  OperationStatus,
                  RequesterContext,
                  ParameterSnapshot->MajorFunction,
                  ParameterSnapshot->MinorFunction,
                  FltGetIrpName(ParameterSnapshot->MajorFunction)));
}

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)

{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("PassThrough!PtPostOperationPassThrough: Entered\n"));

    // Начало
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL; // Объявление структуры
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED |
            FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo); // Парсинг имени файла на составляющие

    UNICODE_STRING required_extension = RTL_CONSTANT_STRING(L"testlabextension"); // Перевод расширения в UNICODE_STRING

    if (!NT_SUCCESS(status))
    {

        // Ничего не выводим, чтобы не загружать оперативную память, DebugView
    }
    else if ( // Проверка на совпадение расширения с нашим шаблоном
        RtlEqualUnicodeString(
            &required_extension,
            &NameInfo->Extension,
            FALSE))
    {
        //проверка на событие IRP_MJ_WRITE
        if (Data->Iopb->MajorFunction == IRP_MJ_WRITE)
        {
            DbgPrint("Write");
            DbgPrint(Data->Iopb->Parameters.Write.WriteBuffer);

            if (Data->Iopb->Parameters.Write.WriteBuffer)
            {
                DbgPrint("Cipher");
                // unsigned char cipher[64];
                uint8_t hexarray[1024];
                memset(hexarray, 0, 1024);
                for (int i = 0; i < strlen(Data->Iopb->Parameters.Write.WriteBuffer); i++)
                {
                    hexarray[i] = (uint8_t)((char *)Data->Iopb->Parameters.Write.WriteBuffer)[i];
                }

                unsigned char KEY[] = "1234567890ABCDEF"; //определение ключа
                uint8_t *key = (uint8_t *)KEY;            //приведение ключа к нужному формату
                uint8_t iv[] = {0x75, 0x52, 0x5f, 0x69,   //инициализирующий вектор
                                0x6e, 0x74, 0x65, 0x72,
                                0x65, 0x73, 0x74, 0x69,
                                0x6e, 0x67, 0x21, 0x21};

                struct AES_ctx ctx; //создание объекта шифра (контекст, который будет хранить ключ и инициализирующий вектор)

                AES_init_ctx_iv(&ctx, key, iv);               //инициализация структуры
                AES_CBC_encrypt_buffer(&ctx, hexarray, 1024); //шифруем буфер (передаем контекст, буфер и длину буфера)

                for (int i = 0; i < 1024; i++)
                {
                    ((char *)Data->Iopb->Parameters.Write.WriteBuffer)[i] = hexarray[i];
                }
            }
        }
        else if ((Data->Iopb->MajorFunction == IRP_MJ_READ) && (Data->Iopb->Parameters.Read.Length != 1))
        {
            DbgPrint("Read");
            DbgPrint(Data->Iopb->Parameters.Read.ReadBuffer);

            if (strlen((char *)Data->Iopb->Parameters.Read.ReadBuffer) != 0)
            {
                DbgPrint("Decipher");
                // unsigned char decipher[64];
                uint8_t hexarray[1024];
                memset(hexarray, 0, 1024);
                for (int i = 0; i < strlen(Data->Iopb->Parameters.Read.ReadBuffer); i++)
                {
                    hexarray[i] = (uint8_t)((char *)Data->Iopb->Parameters.Read.ReadBuffer)[i];
                }

                unsigned char KEY[] = "1234567890ABCDEF"; //определение ключа
                uint8_t *key = (uint8_t *)KEY;            //приведение ключа к нужному формату
                uint8_t iv[] = {0x75, 0x52, 0x5f, 0x69,   //инициализирующий вектор
                                0x6e, 0x74, 0x65, 0x72,
                                0x65, 0x73, 0x74, 0x69,
                                0x6e, 0x67, 0x21, 0x21};

                struct AES_ctx ctx; //создание объекта шифра (контекст, который будет хранить ключ и инициализирующий вектор)

                AES_init_ctx_iv(&ctx, key, iv);               //инициализация структуры
                AES_CBC_decrypt_buffer(&ctx, hexarray, 1024); //расшифруем буфер (передаем контекст, буфер и длину буфера)

                for (int i = 0; i < 1024; i++)
                {
                    ((char *)Data->Iopb->Parameters.Write.WriteBuffer)[i] = hexarray[i];
                }
            }
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)

{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("PassThrough!PtPreOperationNoPostOperationPassThrough: Entered\n"));

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

BOOLEAN
PtDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data)

{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    return (BOOLEAN)

        (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
          ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
           (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
           (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
           (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2))) ||
         ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
          (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY)));
}
