#pragma once
#include <phnt_windows.h>
#include <phnt.h>

#include <intrin.h>
#pragma intrinsic(_BitScanForward)

#include <type_traits>

#include <wil/result.h>
#include <wil/resource.h>
#include <wil/win32_helpers.h>

#define PAGE_EXECUTE_ANY (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define PAGE_EXECUTE_NONE (PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY)
#define PAGE_WRITE_ANY (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOMBINE)
#define PAGE_WRITECOPY_ANY (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

/*
  The ROUND_TO_PAGES macro takes a size in bytes and rounds it up to a
  multiple of the page size.

  NOTE: This macro fails for values 0xFFFFFFFF - (PAGE_SIZE - 1).
  \param Size: Size in bytes to round up to a page multiple.
  \return Returns the size rounded up to a multiple of the page size.
*/
inline ULONG_PTR ROUND_TO_PAGES(IN ULONG_PTR Size)
{
  return ((ULONG_PTR)Size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

/*
  The BYTES_TO_PAGES macro takes the size in bytes and calculates the
  number of pages required to contain the bytes.

  \param Size: Size in bytes.
  \return Returns the number of pages required to contain the specified size.
*/
inline ULONG BYTES_TO_PAGES(IN ULONG Size)
{
  ULONG PageShift;

  if ( !_BitScanForward(&PageShift, PAGE_SIZE) )
    return 0;

  return (ULONG)((ULONG_PTR)Size >> PageShift) + (((ULONG)Size & (PAGE_SIZE - 1)) != 0);
}

/*
  The BYTE_OFFSET macro takes a virtual address and returns the byte offset 
  of that address within the page.

  \param Va: Virtual address.
  \return Returns the byte offset portion of the virtual address.
*/
inline ULONG BYTE_OFFSET(IN PVOID Va)
{
  return (ULONG)((LONG_PTR)Va & (PAGE_SIZE - 1));
}

/*
  The PAGE_ALIGN macro takes a virtual address and returns a page-aligned 
  virtual address for that page.

  \param Va: Virtual address.
  \return Returns the page aligned virtual address.
*/
inline PVOID PAGE_ALIGN(IN PVOID Va)
{
  return (PVOID)((ULONG_PTR)Va & ~(PAGE_SIZE - 1));
}

/*
  The ADDRESS_AND_SIZE_TO_SPAN_PAGES macro takes a virtual address and 
  size and returns the number of pages spanned by the size.

  \param Va: Virtual address.
  \param Size: Size in bytes.
  \return Returns the number of pages spanned by the size.
*/
inline SIZE_T ADDRESS_AND_SIZE_TO_SPAN_PAGES(
  IN PVOID Va,
  IN SIZE_T Size)
{
  ULONG PageShift;

  if ( !_BitScanForward(&PageShift, PAGE_SIZE) )
    return 0;

  return (((Size - 1) >> PageShift) +
    ((((Size - 1) & (PAGE_SIZE - 1)) + ((ULONG_PTR)Va & (PAGE_SIZE - 1))) >> PageShift)) + 1L;
}

namespace nt::rtl
{
  class protect_memory
  {
  private:
    HANDLE process;
    PVOID pointer;
    SIZE_T size;
    ULONG protect;

  public:
    protect_memory() = delete;
    protect_memory(protect_memory &) = delete;

    protect_memory(HANDLE ProcessHandle, PVOID Va, SIZE_T Size, ULONG NewProtect)
      : process(ProcessHandle)
    {
      pointer = PAGE_ALIGN(Va);
      size = ADDRESS_AND_SIZE_TO_SPAN_PAGES(Va, Size) * PAGE_SIZE;
      THROW_IF_NTSTATUS_FAILED(NtProtectVirtualMemory(process, &pointer, &size, NewProtect, &protect));
    }

    protect_memory(PVOID BaseAddress, SIZE_T RegionSize, ULONG NewProtect)
      : protect_memory(NtCurrentProcess(), BaseAddress, RegionSize, NewProtect)
    {
    }

    ~protect_memory()
    {
      THROW_IF_NTSTATUS_FAILED(NtProtectVirtualMemory(process, &pointer, &size, protect, &protect));
    }
  };
}
