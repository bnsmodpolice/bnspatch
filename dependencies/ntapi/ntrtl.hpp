#pragma once
#include <phnt_windows.h>
#include <phnt.h>

#include <utility>
#include <cstddef>
#include <iterator>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

#include <wil/result.h>
#include <wil/resource.h>
#include <wil/win32_helpers.h>

namespace rtl
{
  class critical_section : public RTL_CRITICAL_SECTION
  {
  public:
    using native_handle_type = PRTL_CRITICAL_SECTION;

    critical_section()
    {
      RtlInitializeCriticalSection(this);
    }

    critical_section(unsigned long spinCount)
    {
      RtlInitializeCriticalSectionAndSpinCount(this, spinCount);
    }

    void lock()
    {
      RtlEnterCriticalSection(this);
    }

    bool try_lock()
    {
      return RtlTryEnterCriticalSection(this);
    }

    void unlock()
    {
      RtlLeaveCriticalSection(this);
    }

    native_handle_type native_handle()
    {
      return this;
    }
  };

  class loader_lock
  {
  public:
    using native_handle_type = PVOID;

    void lock()
    {
      (VOID)LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, nullptr, &Cookie);
    }

    bool try_lock()
    {
      ULONG Disposition;
      (VOID)LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS | LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, &Disposition, &Cookie);
      return Disposition == LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED;
    }

    void unlock()
    {
      (VOID)LdrUnlockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, Cookie);
    }

    native_handle_type native_handle()
    {
      return Cookie;
    }

  private:
    PVOID Cookie;
  };

  inline bool starts_with(const UNICODE_STRING &Lhs, const UNICODE_STRING &Rhs)
  {
    return RtlPrefixUnicodeString(&(UNICODE_STRING &)Rhs, &(UNICODE_STRING &)Lhs, FALSE);
  }

  inline bool starts_with(const UNICODE_STRING &Lhs, const WCHAR *Rhs)
  {
    UNICODE_STRING String;
    THROW_IF_NTSTATUS_FAILED(RtlInitUnicodeStringEx(&String, Rhs));
    return starts_with(Lhs, String);
  }

  inline bool starts_with(const ANSI_STRING &Lhs, const ANSI_STRING &Rhs)
  {
    return RtlPrefixString(&(ANSI_STRING &)Rhs, &(ANSI_STRING &)Lhs, FALSE);
  }

  inline bool starts_with(const ANSI_STRING &Lhs, const CHAR *Rhs)
  {
    ANSI_STRING String;
    THROW_IF_NTSTATUS_FAILED(RtlInitAnsiStringEx(&String, Rhs));
    return starts_with(Lhs, String);
  }

  inline bool istarts_with(const UNICODE_STRING &Lhs, const UNICODE_STRING &Rhs)
  {
    return RtlPrefixUnicodeString(&(UNICODE_STRING &)Rhs, &(UNICODE_STRING &)Lhs, TRUE);
  }

  inline bool istarts_with(const UNICODE_STRING &Lhs, const WCHAR *Rhs)
  {
    UNICODE_STRING String;
    THROW_IF_NTSTATUS_FAILED(RtlInitUnicodeStringEx(&String, Rhs));
    return istarts_with(Lhs, String);
  }

  inline bool istarts_with(const ANSI_STRING &Lhs, const ANSI_STRING &Rhs)
  {
    return RtlPrefixString(&(ANSI_STRING &)Rhs, &(ANSI_STRING &)Lhs, TRUE);
  }

  inline bool istarts_with(const ANSI_STRING &Lhs, const CHAR *Rhs)
  {
    ANSI_STRING String;
    THROW_IF_NTSTATUS_FAILED(RtlInitAnsiStringEx(&String, Rhs));
    return istarts_with(Lhs, String);
  }

  inline bool equals(const UNICODE_STRING &Lhs, const UNICODE_STRING &Rhs)
  {
    return RtlEqualUnicodeString(&(UNICODE_STRING &)Lhs, &(UNICODE_STRING &)Rhs, FALSE);
  }

  inline bool equals(const UNICODE_STRING &Lhs, const WCHAR *Rhs)
  {
    UNICODE_STRING String;
    THROW_IF_NTSTATUS_FAILED(RtlInitUnicodeStringEx(&String, Rhs));
    return equals(Lhs, String);
  }

  inline bool equals(const ANSI_STRING &Lhs, const ANSI_STRING &Rhs)
  {
    return RtlEqualString(&(ANSI_STRING &)Lhs, &(ANSI_STRING &)Rhs, FALSE);
  }

  inline bool equals(const ANSI_STRING &Lhs, const CHAR *Rhs)
  {
    ANSI_STRING String;
    THROW_IF_NTSTATUS_FAILED(RtlInitAnsiStringEx(&String, Rhs));
    return equals(Lhs, String);
  }

  inline bool iequals(const UNICODE_STRING &Lhs, const UNICODE_STRING &Rhs)
  {
    return RtlEqualUnicodeString(&(UNICODE_STRING &)Lhs, &(UNICODE_STRING &)Rhs, TRUE);
  }

  inline bool iequals(const UNICODE_STRING &Lhs, const WCHAR *Rhs)
  {
    UNICODE_STRING String;
    THROW_IF_NTSTATUS_FAILED(RtlInitUnicodeStringEx(&String, Rhs));
    return iequals(Lhs, String);
  }

  inline bool iequals(const ANSI_STRING &Lhs, const ANSI_STRING &Rhs)
  {
    return RtlEqualString(&(ANSI_STRING &)Lhs, &(ANSI_STRING &)Rhs, TRUE);
  }

  inline bool iequals(const ANSI_STRING &Lhs, const CHAR *Rhs)
  {
    ANSI_STRING String;
    THROW_IF_NTSTATUS_FAILED(RtlInitAnsiStringEx(&String, Rhs));
    return iequals(Lhs, String);
  }

  inline WCHAR *begin(UNICODE_STRING &String)
  {
    return String.Buffer;
  }

  inline const WCHAR *begin(const UNICODE_STRING &String)
  {
    return String.Buffer;
  }

  inline CHAR *begin(ANSI_STRING &String)
  {
    return String.Buffer;
  }

  inline const CHAR *begin(const ANSI_STRING &String)
  {
    return String.Buffer;
  }

  inline WCHAR *end(UNICODE_STRING &String)
  {
    return (WCHAR *)((CHAR *)String.Buffer + String.Length);
  }

  inline const WCHAR *end(const UNICODE_STRING &String)
  {
    return (WCHAR *)((CHAR *)String.Buffer + String.Length);
  }

  inline CHAR *end(ANSI_STRING &String)
  {
    return String.Buffer + String.Length;
  }

  inline const CHAR *end(const ANSI_STRING &String)
  {
    return String.Buffer + String.Length;
  }

  inline auto rbegin(UNICODE_STRING &String)
  {
    return std::make_reverse_iterator(end(String));
  }

  inline auto rbegin(const UNICODE_STRING &String)
  {
    return std::make_reverse_iterator(end(String));
  }

  inline auto rbegin(ANSI_STRING &String)
  {
    return std::make_reverse_iterator(end(String));
  }

  inline auto rbegin(const ANSI_STRING &String)
  {
    return std::make_reverse_iterator(end(String));
  }

  inline auto rend(UNICODE_STRING &String)
  {
    return std::make_reverse_iterator(begin(String));
  }

  inline auto rend(const UNICODE_STRING &String)
  {
    return std::make_reverse_iterator(begin(String));
  }

  inline auto rend(ANSI_STRING &String)
  {
    return std::make_reverse_iterator(begin(String));
  }

  inline auto rend(const ANSI_STRING &String)
  {
    return std::make_reverse_iterator(begin(String));
  }

  inline auto to_string(const ANSI_STRING &String)
  {
    std::string Str(String.Length + 1, '\0');
    std::copy(begin(String), end(String), Str.begin());
    return Str;
  }

  inline auto to_wstring(const UNICODE_STRING &String)
  {
    std::wstring Str((String.Length >> 1) + 1, '\0');
    std::copy(begin(String), end(String), Str.begin());
    return Str;
  }

  template<class T = void, typename = std::enable_if_t<std::is_void_v<T> || std::is_pod_v<T> || std::is_function_v<T>>>
  inline T *image_rva_to_va(PVOID Base, ULONG_PTR Rva)
  {
    if ( !Base )
      Base = NtCurrentPeb()->ImageBaseAddress;

    return Rva ? reinterpret_cast<T *>(reinterpret_cast<PUCHAR>(Base) + Rva) : nullptr;
  }

  inline PIMAGE_NT_HEADERS image_nt_headers(PVOID Base)
  {
    if ( !Base )
      Base = NtCurrentPeb()->ImageBaseAddress;

    const auto DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Base);
    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE )
      return nullptr;

    const auto NtHeaders = image_rva_to_va<IMAGE_NT_HEADERS>(Base, DosHeader->e_lfanew);
    if ( !NtHeaders
      || NtHeaders->Signature != IMAGE_NT_SIGNATURE
      || !NtHeaders->FileHeader.SizeOfOptionalHeader )
      return nullptr;

    return NtHeaders;
  }

  template<class T = UCHAR, typename = std::enable_if_t<std::is_pod_v<T>>>
  inline T *image_directory_entry_to_data(PVOID Base, USHORT DirectoryEntry, ULONG *Count = nullptr)
  {
    const auto NtHeaders = rtl::image_nt_headers(Base);
    if ( !NtHeaders
      || NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC )
      return nullptr;

    if ( DirectoryEntry >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes
      || !NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress
      || !NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].Size )
      return nullptr;

    if ( Count )
      *Count = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].Size / sizeof(T);

    return image_rva_to_va<T>(Base, NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress);
  }

  inline PVOID image_entry_point(PVOID Base)
  {
    const auto NtHeaders = rtl::image_nt_headers(Base);
    if ( !NtHeaders ) return nullptr;

    const auto ClrHeader = rtl::image_directory_entry_to_data<IMAGE_COR20_HEADER>(Base, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    if ( ClrHeader ) {
      const auto hClr = GetModuleHandleW(L"mscoree.dll");
      return hClr ? GetProcAddress(hClr, "_CorExeMain") : nullptr;
    }
    return image_rva_to_va(Base, NtHeaders->OptionalHeader.AddressOfEntryPoint);
  }

  inline ULONG image_size(PVOID Base)
  {
    const auto NtHeaders = rtl::image_nt_headers(Base);
    return NtHeaders ? NtHeaders->OptionalHeader.SizeOfImage : 0;
  }

  inline PVOID pc_to_image_base(PVOID PcValue)
  {
    MEMORY_BASIC_INFORMATION mbi;

    if ( !PcValue
      || VirtualQuery(PcValue, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0
      || (mbi.State != MEM_COMMIT || (mbi.Protect & 0xff) == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) )
      return nullptr;

    return mbi.AllocationBase;
  }

  inline PLDR_DATA_TABLE_ENTRY pc_to_ldr_data_table_entry(PVOID PcValue)
  {
    if ( !PcValue )
      return nullptr;

    const std::unique_lock<rtl::loader_lock> lock{};
    const auto ModuleList = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    for ( auto Next = ModuleList->Flink; Next != ModuleList; Next = Next->Flink ) {
      const auto Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
      const auto Low = reinterpret_cast<UCHAR *>(Entry->DllBase);
      if ( PcValue >= Low && PcValue < Low + Entry->SizeOfImage )
        return Entry;
    }
    return nullptr;
  }

  inline std::span<IMAGE_SECTION_HEADER> image_sections(PVOID Base)
  {
    const auto NtHeaders = image_nt_headers(Base);
    const auto Ptr = reinterpret_cast<PIMAGE_SECTION_HEADER>(
      reinterpret_cast<ULONG_PTR>(NtHeaders) + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + NtHeaders->FileHeader.SizeOfOptionalHeader);

    return {Ptr, NtHeaders->FileHeader.NumberOfSections};
  }

  inline auto find_image_section_by_name(const std::span<IMAGE_SECTION_HEADER> &Sections, PCSTR Name)
  {
    return std::find_if(Sections.begin(), Sections.end(), [&](const IMAGE_SECTION_HEADER &Section) {
      if ( !Name )
        return true;

      SIZE_T Size;
      for ( Size = 0; Size < IMAGE_SIZEOF_SHORT_NAME; ++Size ) {
        if ( !Section.Name[Size] )
          break;
      }
      return std::string_view{reinterpret_cast<PCSTR>(Section.Name), Size} == Name;
    });
  }

  inline std::span<IMAGE_RUNTIME_FUNCTION_ENTRY> lookup_function_table(PVOID ControlPc, PVOID *DllBase = nullptr)
  {
    std::unique_lock<rtl::loader_lock> lock{};
    const auto ModuleList = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    for ( auto Next = ModuleList->Flink; Next != ModuleList; Next = Next->Flink ) {
      const auto Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
      if ( (ControlPc >= Entry->DllBase)
        && (ControlPc < reinterpret_cast<PUCHAR>(Entry->DllBase) + Entry->SizeOfImage) ) {

        if ( DllBase )
          *DllBase = Entry->DllBase;

        ULONG Count;
        const auto FunctionTable = image_directory_entry_to_data<IMAGE_RUNTIME_FUNCTION_ENTRY>(Entry->DllBase, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &Count);
        if ( FunctionTable )
          return {FunctionTable, Count};
        return {};
      }
    }
    return {};
  }
}
