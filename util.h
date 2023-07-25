#pragma once

#define OB_FILE_OBJECT_TYPE 0x1

#define STATUS_SUCCESS                ((DWORD)0x000000000)
#define STATUS_INSUFFICIENT_RESOURCES ((DWORD)0xC0000009A)

#define LOCATE_MSG_CONTENT(buf) ((ULONG_PTR)buf + sizeof(PORT_MESSAGE64))

#define SECRET ((DWORD)0x1802ABCD)
#define SERVER_PORTNAME L"\\RPC Control\\My ALPC Test Port"
#define SAYHI "Hello"

PORT_MESSAGE64 *AllocPortMsgBuffer(SIZE_T BufferSize);
VOID FreePortMsgBuffer(PORT_MESSAGE64 *BufferPtr);
PALPC_MESSAGE_ATTRIBUTES AllocMessageAttributes(ULONG AttributeFlags);
VOID FreeMessageAttributes(PALPC_MESSAGE_ATTRIBUTES Attributes);