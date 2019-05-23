#include <Windows.h>


int main()
{
	LPVOID allocated_memory = VirtualAlloc(NULL, 1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (allocated_memory)
	{
		memset(allocated_memory, 0, 1000);
	}
}
