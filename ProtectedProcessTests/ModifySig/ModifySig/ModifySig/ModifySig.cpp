// ModifySig.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{

	HANDLE hVolume = CreateFile(L"\\\\.\\C:", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hVolume == INVALID_HANDLE_VALUE)
	{
		cout << "Error opening file." << endl;
	}
	else
	{
		cout << "File opened successfully." << endl;
	}

	const DWORD size = 512;
	LPVOID buffer = new byte[size];
	DWORD bytesRead = 0;
	DWORD bytesWritten = 0;
	if (ReadFile(hVolume, buffer, size, &bytesRead, NULL))
	{
		if (WriteFile(hVolume, buffer, bytesRead, &bytesWritten, NULL))
		{
			cout << "Successfully wrote to the C volume. Wrote " << bytesRead << " bytes." << endl;
		}
		else
		{
			cout << "Error writing to C volume." << endl;
		}
	}
	else
	{
		cout << "Error reading from C volume." << endl;
	}

	string in = "";
	cout << "Press any key to continue." << endl;
	getline(cin, in);

	return 0;
}

