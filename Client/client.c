#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#include "..\ntalpcapi.h"
#include "..\util.h"

#pragma comment(lib,"ntdll.lib")

int main(void)
{
    NTSTATUS                            status = STATUS_SUCCESS;
    HANDLE                              hFile = INVALID_HANDLE_VALUE;
    HANDLE                              hCommPort = NULL;
    UNICODE_STRING                      uServerPortName = { 0 };
    ALPC_PORT_ATTRIBUTES                alpcAttr = { 0 };
    PORT_MESSAGE64                      *msgBuffer = NULL, *receiveBuffer = NULL;
    SIZE_T                              szLen = 0;
    ALPC_MESSAGE_ATTRIBUTES             *msgAttributes = NULL;
    ALPC_MESSAGE_HANDLE_INFORMATION     *handleAttributes = NULL;

    hFile = CreateFileW(L"C:\\Windows\\Temp\\my_alpc_test_log.txt", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Creating log file failed : 0x%08X\n", GetLastError());
        return 0;
    }

    /* Initialize buffers */

    RtlInitUnicodeString(&uServerPortName, SERVER_PORTNAME);
    alpcAttr.MaxMessageLength = AlpcMaxAllowedMessageLength();

    szLen = AlpcMaxAllowedMessageLength();

    msgBuffer = AllocPortMsgBuffer(szLen);
    if (!msgBuffer) {
        printf("[-] Allocate message buffer failed : 0x%08X\n", STATUS_INSUFFICIENT_RESOURCES);
        goto out;
    }

    receiveBuffer = AllocPortMsgBuffer(szLen);
    if (!receiveBuffer) {
        printf("[-] Allocate message buffer failed : 0x%08X\n", STATUS_INSUFFICIENT_RESOURCES);
        goto out;
    }

    /* Write secret */

    *(DWORD *)LOCATE_MSG_CONTENT(msgBuffer) = SECRET;

    msgBuffer->u1.s1.DataLength = sizeof(SECRET);
    msgBuffer->u1.s1.TotalLength = sizeof(SECRET) + sizeof(PORT_MESSAGE64);

    /* Connect to server */

    status = NtAlpcConnectPort(
        &hCommPort,
        &uServerPortName,
        NULL,
        &alpcAttr,
        ALPC_MSGFLG_SYNC_REQUEST,
        NULL,
        msgBuffer,
        &szLen,
        NULL,
        NULL,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to connect to server : 0x%08X\n", status);
        goto out;
    }

    printf("[+] Connected with server, client communication handle : 0x%x\n", (DWORD)hCommPort);

    /* Share handle */

    msgAttributes = AllocMessageAttributes(ALPC_MESSAGE_HANDLE_ATTRIBUTE);
    msgAttributes->ValidAttributes |= ALPC_MESSAGE_HANDLE_ATTRIBUTE;

    handleAttributes = AlpcGetMessageAttribute(msgAttributes, ALPC_MESSAGE_HANDLE_ATTRIBUTE);
    handleAttributes->Handle = hFile;
    handleAttributes->Flags = ALPC_HANDLEFLG_DUPLICATE_SAME_ACCESS;

    /* Send a friendly message along with handle */

    RtlZeroMemory(msgBuffer, AlpcMaxAllowedMessageLength() + sizeof(PORT_MESSAGE64));
    RtlCopyMemory(LOCATE_MSG_CONTENT(msgBuffer), SAYHI, strlen(SAYHI));

    msgBuffer->u1.s1.DataLength = strlen(SAYHI);
    msgBuffer->u1.s1.TotalLength = strlen(SAYHI) + sizeof(PORT_MESSAGE64);

    status = NtAlpcSendWaitReceivePort(
        hCommPort,
        ALPC_MSGFLG_SYNC_REQUEST,
        msgBuffer,
        msgAttributes,
        receiveBuffer,
        &szLen,
        NULL,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to send message to server : 0x%08X\n", status);
        goto out;
    }

    puts("[+] Send message success");

out:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    if (msgBuffer)
        FreePortMsgBuffer(msgBuffer);

    if (receiveBuffer)
        FreePortMsgBuffer(receiveBuffer);

    if (msgAttributes)
        FreeMessageAttributes(msgAttributes);

    if (hCommPort)
        CloseHandle(hCommPort);

    puts(":goodbye");
    return 0;
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