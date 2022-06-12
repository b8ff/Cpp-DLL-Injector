#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <conio.h>
#include <string>

DWORD get_process_id(const char* process_name){
    DWORD process_id = 0;
    HANDLE help_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (help_snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 process_entry;
        process_entry.dwSize = sizeof(process_entry);

        if (Process32First(help_snapshot, &process_entry))
        {
            do
            {
                if (!_stricmp(process_entry.szExeFile, process_name))
                {
                    process_id = process_entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(help_snapshot, &process_entry));
        }
    }
    CloseHandle(help_snapshot);
    return process_id;
}

void injector(std::string process_name_raw, std::string dll_path_raw){
	const char* dll_path = dll_path_raw.c_str();
    const char* process_name = process_name_raw.c_str();
	DWORD process_id = 0;

    while (!process_id)
    {
        process_id = get_process_id(process_name);
        Sleep(30);
    }

    HANDLE handle_process = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);

    if (handle_process && handle_process != INVALID_HANDLE_VALUE)
    {
        void* loc = VirtualAllocEx(handle_process, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        WriteProcessMemory(handle_process, loc, dll_path, strlen(dll_path) + 1, 0);

        HANDLE handle_thread = CreateRemoteThread(handle_process, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

        if (handle_thread)
        {
            CloseHandle(handle_thread);
        }
    }

    if (handle_process)
    {
        CloseHandle(handle_process);
    }
}

int main(){
	std::string dll;
	std::string process;
	
	std::cout << "Enter the DLL path: ";
	std::cin >> dll;
	std::cout << "Enter the process name (Example: Minecraft.Windows.exe): ";
	std::cin >> process;
	
	injector(process, dll);
	
	std::cout << "DLL injected successfully!";
	getch();
	
	return 0;
}
