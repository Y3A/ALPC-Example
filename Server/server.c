#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#include "..\ntalpcapi.h"
#include "..\util.h"

#pragma comment(lib,"ntdll.lib")

int main(void)
{
    NTSTATUS status = AlpcCreateListenPort(SERVER_PORTNAME);

    return 0;
}

NTSTATUS AlpcCreateListenPort(LPCWSTR PortName)
{
    ALPC_PORT_ATTRIBUTES                    alpcAttr = { 0 };
    OBJECT_ATTRIBUTES                       objAttr = { 0 };
    UNICODE_STRING                          uPortName = { 0 };
    NTSTATUS                                status = STATUS_SUCCESS;
    HANDLE                                  hConnPort = NULL, hCommPort = NULL;
    PORT_MESSAGE64                          acceptRequest = { 0 };
    PORT_MESSAGE64                          *msgBuffer = NULL;
    BOOL                                    accept = FALSE;
    SIZE_T                                  szLen = 0;
    ALPC_MESSAGE_ATTRIBUTES                 *msgAttr = NULL;
    ALPC_MESSAGE_HANDLE_INFORMATION         *handleAttr = NULL;
    HANDLE                                  receivedHandle = NULL;

    /* Create server connection port */

    RtlInitUnicodeString(&uPortName, PortName);
    InitializeObjectAttributes(&objAttr, &uPortName, 0, NULL, NULL);

    alpcAttr.MaxMessageLength = AlpcMaxAllowedMessageLength();

    /* Allow receiving file handle from client */

    alpcAttr.DupObjectTypes = OB_FILE_OBJECT_TYPE;
    alpcAttr.Flags = ALPC_PORTFLG_ALLOW_DUP_OBJECT;

    status = NtAlpcCreatePort(&hConnPort, &objAttr, &alpcAttr);
    if (!NT_SUCCESS(status)) {
        printf("[-] Create server connection port failed : 0x%08X\n", status);
        hConnPort = NULL;
        goto out;
    }

    printf("[+] Server Connection Port created with handle : 0x%x\n", (DWORD)hConnPort);

    /* Allocate Buffers */

    szLen = AlpcMaxAllowedMessageLength();

    msgBuffer = AllocPortMsgBuffer(szLen);
    if (!msgBuffer) {
        printf("[-] Allocate message buffer failed : 0x%08X\n", STATUS_INSUFFICIENT_RESOURCES);
        goto out;
    }

    /* Listen for connection request */

    szLen = sizeof(SECRET) + sizeof(PORT_MESSAGE64);

    status = NtAlpcSendWaitReceivePort(hConnPort, 0, NULL, NULL, msgBuffer, &szLen, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[-] Listening failed : 0x%08X\n", status);
        goto out;
    }

    /* Accept connection if secret is correct */

    if (*(DWORD *)LOCATE_MSG_CONTENT(msgBuffer) == SECRET)
        accept = TRUE;
    
    acceptRequest.MessageId = msgBuffer->MessageId;
    acceptRequest.u1.s1.DataLength = 0;
    acceptRequest.u1.s1.TotalLength = sizeof(PORT_MESSAGE64);

    status = NtAlpcAcceptConnectPort(&hCommPort, hConnPort, 0, NULL, &alpcAttr, NULL, &acceptRequest, NULL, accept);
    if (!NT_SUCCESS(status)) {
        printf("[-] Accept/Reject failed : 0x%08X\n", status);
        goto out;
    }
    if (!accept) {
        puts("[-] Secret check failed.");
        goto out;
    }

    printf("[+] Accepted connection, Server Communication Port established with handle : 0x%x\n", (ULONG)hCommPort);

    /* Initialize buffer to hold incoming handle */

    msgAttr = AllocMessageAttributes(ALPC_MESSAGE_HANDLE_ATTRIBUTE);
    if (!msgAttr) {
        printf("[-] Allocate message attribute failed : 0x%08X\n", STATUS_INSUFFICIENT_RESOURCES);
        goto out;
    }

    while (1) {

        /* Server message loop */

        szLen = AlpcMaxAllowedMessageLength();
        RtlSecureZeroMemory(msgBuffer, szLen + sizeof(PORT_MESSAGE64));

        status = NtAlpcSendWaitReceivePort(hConnPort, 0, NULL, NULL, msgBuffer, &szLen, msgAttr, NULL);
        if (!NT_SUCCESS(status)) {
            printf("[-] Receive message failed : 0x%08X\n", status);
            goto out;
        }

        /* Extract message and handle if exists */

        printf("[+] Message: %s\n", (char *)(LOCATE_MSG_CONTENT(msgBuffer)));
        if (msgAttr->ValidAttributes & ALPC_MESSAGE_HANDLE_ATTRIBUTE) {
            handleAttr = AlpcGetMessageAttribute(msgAttr, ALPC_MESSAGE_HANDLE_ATTRIBUTE);
            if (handleAttr) {
                DWORD written;
                receivedHandle = handleAttr->Handle;
                printf("[+] Handle: 0x%x\n", (DWORD)receivedHandle);
                WriteFile(receivedHandle, "logloglog", 9, &written, NULL);
            }
        }
    }

out:
    if (hConnPort)
        CloseHandle(hConnPort);
    
    if (hCommPort)
        CloseHandle(hCommPort);

    if (msgBuffer)
        FreePortMsgBuffer(msgBuffer);

    if (msgAttr)
        FreeMessageAttributes(msgAttr);

    /* It's now our responsibility to close this handle */

    if (receivedHandle)
        CloseHandle(receivedHandle);

    return status;
}

PORT_MESSAGE64 *AllocPortMsgBuffer(SIZE_T BufferSize)
{
    return (PORT_MESSAGE64 *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PORT_MESSAGE64) + BufferSize);
}

VOID FreePortMsgBuffer(PORT_MESSAGE64 *BufferPtr)
{
    HeapFree(GetProcessHeap(), 0, BufferPtr);
    return;
}

PALPC_MESSAGE_ATTRIBUTES AllocMessageAttributes(ULONG AttributeFlags)
{
    NTSTATUS                    status = STATUS_SUCCESS;
    PALPC_MESSAGE_ATTRIBUTES    attributeBuffer;
    SIZE_T                      allocSize, requiredSize;

    allocSize = AlpcGetHeaderSize(AttributeFlags);
    attributeBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, allocSize);
    if (!attributeBuffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    status = AlpcInitializeMessageAttribute(AttributeFlags, attributeBuffer, allocSize, &requiredSize);

out:
    if (!NT_SUCCESS(status)) {
        if (attributeBuffer) {
            FreeMessageAttributes(attributeBuffer);
            attributeBuffer = NULL;
        }
    }

    return attributeBuffer;
}

VOID FreeMessageAttributes(PALPC_MESSAGE_ATTRIBUTES Attributes)
{
    HeapFree(GetProcessHeap(), 0, Attributes);
    return;
}