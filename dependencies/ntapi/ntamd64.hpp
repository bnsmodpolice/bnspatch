#pragma once
#include <phnt.h>
#include <phnt_windows.h>
#include <utility>
#include <span>

#include "ntrtl.hpp"

#ifdef _AMD64_
namespace nt::amd64
{
  inline PRUNTIME_FUNCTION convert_function_entry(PRUNTIME_FUNCTION FunctionEntry,
                                                  PVOID ImageBase)
  {
    if ( FunctionEntry && (FunctionEntry->UnwindData & RUNTIME_FUNCTION_INDIRECT) )
      return rtl::image_rva_to_va<RUNTIME_FUNCTION>(ImageBase, FunctionEntry->UnwindData - 1);
    return FunctionEntry;
  }

  inline PRUNTIME_FUNCTION lookup_function_entry(PVOID ControlPc, PVOID *ImageBase)
  {
    PVOID DllBase;
    const auto A = rtl::lookup_function_table(ControlPc, &DllBase);
    if ( ImageBase )
      *ImageBase = DllBase;
    if ( A.empty() )
      return nullptr;

    std::size_t L = 0;
    std::size_t R = A.size() - 1;
    const auto T = reinterpret_cast<PUCHAR>(ControlPc) - reinterpret_cast<PUCHAR>(DllBase);
    while ( L <= R ) {
      const auto m = (L + R) >> 1;
      if ( A[m].EndAddress <= T )
        L = m + 1;
      else if ( A[m].BeginAddress > T )
        R = m - 1;
      else
        return convert_function_entry(std::addressof(A[m]), DllBase);
    }
    return nullptr;
  }
}
#endif
