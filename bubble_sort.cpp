#include <windows.h>
#include <stdint.h>

typedef int (__cdecl *pRand)(void);
typedef void* (__cdecl *pMalloc)(size_t);
typedef void (__cdecl *pFree)(void*);
typedef int (WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
typedef void (WINAPI *pExitProcess)(UINT);

#pragma function(memcpy)

// Custom memcpy
void *memcpy(void *dest, const void *src, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (count--) *d++ = *s++;
    return dest;
}


// Resolve kernel32 base via PEB
HMODULE get_kernel32_base() {
    PVOID peb = (PVOID)__readgsqword(0x60);
    PVOID ldr = *(PVOID*)((BYTE*)peb + 0x18);
    PVOID list = *(PVOID*)((BYTE*)ldr + 0x10);
    PVOID firstEntry = *(PVOID*)((BYTE*)list);
    PVOID secondEntry = *(PVOID*)((BYTE*)firstEntry);
    return *(HMODULE*)((BYTE*)secondEntry + 0x30);
}

template<typename T>
class vector {
private:
    T* data;
    size_t capacity;
    size_t size;
    pMalloc mallocFn;
    pFree freeFn;

public:
    vector(size_t initialSize, pMalloc m, pFree f)
        : capacity(initialSize), size(0), mallocFn(m), freeFn(f) {
        data = (T*)mallocFn(sizeof(T) * capacity);
    }

    ~vector() {
        freeFn(data);
    }

    size_t Size() const { return size; }

    T& operator[](size_t index) { return data[index]; }

    void push_back(const T& value) {
        if (size >= capacity) {
            capacity = capacity == 0 ? 1 : capacity * 2;
            T* newData = (T*)mallocFn(sizeof(T) * capacity);
            for (size_t i = 0; i < size; ++i) {
                newData[i] = data[i];
            }
            freeFn(data);
            data = newData;
        }
        data[size++] = value;
    }
};

void Sort(vector<int>& arr) {
    int n = arr.Size();
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    HMODULE hKernel32 = get_kernel32_base();
    FARPROC (*GetProcAddressFn)(HMODULE, LPCSTR) = (FARPROC (*)(HMODULE, LPCSTR))GetProcAddress(hKernel32, "GetProcAddress");
    HMODULE (*LoadLibraryAFn)(LPCSTR) = (HMODULE (*)(LPCSTR))GetProcAddressFn(hKernel32, "LoadLibraryA");

    HMODULE hMsvcrt = LoadLibraryAFn("msvcrt.dll");
    HMODULE hUser32 = LoadLibraryAFn("user32.dll");

    pRand randFn = (pRand)GetProcAddressFn(hMsvcrt, "rand");
    pMalloc mallocFn = (pMalloc)GetProcAddressFn(hMsvcrt, "malloc");
    pFree freeFn = (pFree)GetProcAddressFn(hMsvcrt, "free");
    pMessageBoxA MessageBoxA = (pMessageBoxA)GetProcAddressFn(hUser32, "MessageBoxA");

    int k = 50000;
    vector<int> brr(k, mallocFn, freeFn);

    for (int j = 0; j < k; ++j) {
        brr.push_back(randFn());
    }

    Sort(brr);

    MessageBoxA(NULL, "Sort complete!", "Status", MB_OK);
    pExitProcess ExitProcessFn = (pExitProcess)GetProcAddressFn(hKernel32, "ExitProcess");
	ExitProcessFn(0);
}
