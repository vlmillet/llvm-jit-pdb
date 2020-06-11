// license [
// This file is part of the LLVMJITPDB project. Copyright 2020 Vivien Millet.
// Distributed under the Apache License 2.0. Text available here at
// https://github.com/vlmillet/llvmjitpdb
// ]

#include <llvm/JITPDB/JITPDBMemoryManager.h>

#pragma warning(push, 0)
#include <llvm/Object/COFF.h>
#pragma warning(pop)
#include <windows.h>

namespace {
enum class LogKind { Information, Warning, Error };
}

#define LLVM_JIT_PDB_LOG(Kind, ...)                                            \
  if (LogKind::Kind == LogKind::Warning || LogKind::Kind == LogKind::Error ||  \
      Verbose) {                                                               \
    printf(#Kind ": " __VA_ARGS__);                                            \
    printf("\n");                                                              \
  }

extern char JITPDB_HCK[];
extern char JITPDB_DLL[];
extern unsigned long long JITPDB_DLL_SIZE;

struct UNWIND_CODE {
  uint8_t OffsetInProlog;
  uint8_t UnwindOpCode : 4;
  uint8_t OpInfo : 4;
};

struct UNWIND_INFO {
  uint8_t Version : 3;
  uint8_t Flags : 5;
  uint8_t SizeOfProlog;
  uint8_t CountOfUnwindCodes;
  uint8_t FrameRegister : 4;
  uint8_t FrameRegisterOffset : 4;
  UNWIND_CODE UnwindCodeArray[256];
} uw;

namespace llvm {
namespace {
const char *SectionNames[4] = {".text", ".rdata", ".pdata", ".xdata"};

int acquireCryptHandle(HCRYPTPROV &handle) {
  if (::CryptAcquireContextW(&handle, 0, 0, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    return 0;

  int errval = ::GetLastError();
  if (errval != NTE_BAD_KEYSET)
    return errval;

  if (::CryptAcquireContextW(&handle, 0, 0, PROV_RSA_FULL,
                             CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT |
                                 CRYPT_SILENT))
    return 0;

  errval = ::GetLastError();
  // Another thread could have attempted to create the keyset at the same time.
  if (errval != NTE_EXISTS)
    return errval;

  if (::CryptAcquireContextW(&handle, 0, 0, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    return 0;

  return ::GetLastError();
}
bool osCrypt(void *buf, std::size_t len) {
  HCRYPTPROV handle;
  int errval = acquireCryptHandle(handle);

  if (!errval) {
    BOOL gen_ok =
        ::CryptGenRandom(handle, (DWORD)len, static_cast<unsigned char *>(buf));
    if (!gen_ok)
      errval = ::GetLastError();
    ::CryptReleaseContext(handle, 0);
  }

  if (!errval)
    return true;

  return false;
}
uint64_t randInteger() {
  char ran[] = "123456789abcdef";

  assert(sizeof(ran) == 16);
  const int max_nibbles = sizeof(ran);

  int nibbles_used = max_nibbles;

  uint64_t result = 0;
  for (uint32_t i = 0; i < sizeof(uint64_t) * 2; ++i) {
    if (nibbles_used == max_nibbles) {
      if (!osCrypt(ran, sizeof(ran)))
        return 0;
      nibbles_used = 0;
    }
    int c = ran[nibbles_used / 2];
    c >>= 4 * (nibbles_used++ & 1);
    result |= uint64_t(c & 0xf) << (i * 4);
  }

  return result;
}

std::string guidToStr(codeview::GUID const &guid) {
  static const char *Lookup = "0123456789ABCDEF";
  std::string res;
  for (int i = 0; i < 16;) {
    uint8_t Byte = guid.Guid[i];
    uint8_t HighNibble = (Byte >> 4) & 0xF;
    uint8_t LowNibble = Byte & 0xF;
    res += Lookup[HighNibble];
    res += Lookup[LowNibble];
    ++i;
    if (i >= 4 && i <= 10 && i % 2 == 0)
      res += '-';
  }
  return std::move(res);
}

} // namespace
JITPDBMemoryManager::JITPDBMemoryManager(
    StringRef PdbPath, std::function<void(void *)> NotifyModuleEmittedCB)
    : PdbPath(PdbPath), NotifyModuleEmitted(NotifyModuleEmittedCB) {
  // auto& NextGUID = getNextBuildGuid();
#define PDB_GUID_TEST 0
#if PDB_GUID_TEST
  uint64_t lo = 0x0123456789ABCDEF;
  uint64_t hi = 0xFEDCBA9876543210;
#else
  uint64_t lo = randInteger();
  uint64_t hi = randInteger();
#endif
  memcpy(Guid.Guid, &lo, sizeof(lo));
  memcpy(&Guid.Guid[8], &hi, sizeof(hi));

  auto lastSlash = this->PdbPath.find_last_of("\\/");
  PdbName = PdbPath;
  OutputPath = ".";
  if (lastSlash != StringRef::npos) {
    OutputPath = PdbPath.substr(0, lastSlash);
    PdbName = PdbPath.substr(lastSlash + 1);
  }
  sys::fs::create_directories(OutputPath);

  DllPath = PdbPath.substr(0, PdbPath.find_last_of('.'));
  DllPath += ".dll";

  // read hack inf (generated .cpp file contains the data related to dll/pdb
  // hacking offsets)
  memcpy(&DllHackInfoData, JITPDB_HCK, sizeof(DllHackInfo));

  // we use only the backing dll .text section for storing code+dataR+dataRW
  MemorySize = DllHackInfoData.SectionInfos[DllHackInfo::TEXT].Size;

  createDll();
  loadDll();

  MemoryStart = (uint8_t *)(DllBaseAddress) +
                DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress;
  CodeSection.mem.addr = MemoryStart;
  CodeSection.mem.size = MemorySize / 2;
  CodeSection.cur = CodeSection.mem.addr;
  assert((CodeSection.mem.size % 128) == 0);
  DataRSection.mem.addr = CodeSection.mem.addr + CodeSection.mem.size;
  DataRSection.mem.size = MemorySize / 4;
  DataRSection.cur = DataRSection.mem.addr;
  DataRWSection.mem.addr = DataRSection.mem.addr + DataRSection.mem.size;
  DataRWSection.mem.size = MemorySize / 4;
  DataRWSection.cur = DataRWSection.mem.addr;
}

JITPDBMemoryManager::~JITPDBMemoryManager() {
  unloadDll();
  // --destroyDll();-- => don't destroy dll for profiling purpose
}

void JITPDBMemoryManager::createDll() {
  FILE *fn = NULL;
  int remainingTries = 10;
  while (remainingTries--) {
#pragma warning(push, 0)
    if ((fn = fopen(DllPath.c_str(), "wb")))
#pragma warning(pop)
    {
      fwrite(JITPDB_DLL, JITPDB_DLL_SIZE, 1, fn);
      fclose(fn);
      break;
    }
  }
}

#define LLVM_JIT_PDB_STRING_AS_PRINTF_ARG(str) int(str.size()), str.data()

void JITPDBMemoryManager::reloadDll() {
  LLVM_JIT_PDB_LOG(Information,
                   "\n\t%.*s Jit Status\n"
                   "\t\t-Code memory usage : %d%%\n"
                   "\t\t-DataRW memory usage : %d%%\n"
                   "\t\t-DataRO memory usage : %d%%\n",
                   LLVM_JIT_PDB_STRING_AS_PRINTF_ARG(DllPath),
                   int(100 * (CodeSection.cur - CodeSection.mem.addr) /
                       CodeSection.mem.size),
                   int(100 * (DataRWSection.cur - DataRWSection.mem.addr) /
                       DataRWSection.mem.size),
                   int(100 * (DataRSection.cur - DataRSection.mem.addr) /
                       DataRSection.mem.size));

  uint8_t *backupMem = (uint8_t *)::malloc(MemorySize);

  ptrdiff_t codeOff = (char *)CodeSection.mem.addr - (char *)MemoryStart;
  ptrdiff_t dataROff = (char *)DataRSection.mem.addr - (char *)MemoryStart;
  ptrdiff_t dataRWOff = (char *)DataRWSection.mem.addr - (char *)MemoryStart;

  ptrdiff_t codeOffInFile =
      codeOff + DllHackInfoData.SectionInfos[DllHackInfo::TEXT].FilePos;
  ptrdiff_t dataROffInFile =
      dataROff + DllHackInfoData.SectionInfos[DllHackInfo::TEXT].FilePos;
  ptrdiff_t dataRWOffInFile =
      dataRWOff + DllHackInfoData.SectionInfos[DllHackInfo::TEXT].FilePos;

  if (CodeSection.mem.addr)
    memcpy(backupMem + codeOff, CodeSection.mem.addr, CodeSection.mem.size);
  if (DataRSection.mem.addr)
    memcpy(backupMem + dataROff, DataRSection.mem.addr, DataRSection.mem.size);
  if (DataRWSection.mem.addr)
    memcpy(backupMem + dataRWOff, DataRWSection.mem.addr,
           DataRWSection.mem.size);

  unloadDll();

#define MEMORY_CONSISTENCY_TEST 0
#if MEMORY_CONSISTENCY_TEST
  if (rand() < (RAND_MAX / 2)) {
    VirtualAlloc(
        MemoryStart -
            DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress,
        DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  }
#endif

  // hack dll content
#pragma warning(disable : 4996)
  FILE *dllFD = fopen(DllPath.c_str(), "rb+");
#pragma warning(default : 4996)
  assert(dllFD);

  // rewrite time stamp
  time_t currTime;
  time(&currTime);
  fseek(dllFD, DllHackInfoData.TimeStampPos, 0);
  fwrite(&currTime, 4, 1, dllFD);

  // make the memory only readable
  uint8_t writeHack = 0x60;
  fseek(dllFD, DllHackInfoData.SectionInfos[DllHackInfo::TEXT].HeaderPos + 39,
        0);
  fwrite(&writeHack, 1, 1, dllFD);

  ULONG_PTR imageBase =
      (ULONG_PTR)backupMem -
      DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress;
  UNWIND_INFO *unwindInfos =
      (UNWIND_INFO *)((uint8_t *)imageBase + UWDataOffset);
  RUNTIME_FUNCTION *functions =
      (RUNTIME_FUNCTION *)((uint8_t *)imageBase + RFDataOffset);

  size_t supposedCount = RFDataSize / sizeof(RUNTIME_FUNCTION);
  size_t realCount = 0;

  // copy old unwind infos from .dll .pdata section (this allows us to see where
  // unwind infos start)
  fseek(dllFD, DllHackInfoData.SectionInfos[DllHackInfo::PDATA].FilePos, 0);
  RUNTIME_FUNCTION oldTableFirstFunc;
  fread(&oldTableFirstFunc, sizeof(RUNTIME_FUNCTION), 1, dllFD);

  DWORD offsetOtUnwindInfosInRData =
      oldTableFirstFunc.UnwindData -
      DllHackInfoData.SectionInfos[DllHackInfo::RDATA].VirtualAddress;

  // go to unwind data pos in file and write the new unwind data here
  // first zero memory
  char zero = 0;
  fseek(dllFD,
        DllHackInfoData.SectionInfos[DllHackInfo::RDATA].FilePos +
            offsetOtUnwindInfosInRData,
        0);
  fwrite(&zero, 1, DllHackInfoData.SectionInfos[DllHackInfo::XDATA].Size,
         dllFD);
  // then copy
  fseek(dllFD,
        DllHackInfoData.SectionInfos[DllHackInfo::RDATA].FilePos +
            offsetOtUnwindInfosInRData,
        0);
  fwrite(unwindInfos, UWDataSize, 1, dllFD);

  RUNTIME_FUNCTION *functionsp = functions;
  for (realCount = 0; realCount < supposedCount; ++realCount) {
    RUNTIME_FUNCTION &func = *functionsp++;
    if (func.BeginAddress == 0xCCCCCCCC) // out of bound
      break;
    func.BeginAddress +=
        DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress;
    func.EndAddress +=
        DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress;
    func.UnwindInfoAddress +=
        DWORD(DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress -
              UWDataOffset + oldTableFirstFunc.UnwindData);
  }

  size_t maxCount = (DllHackInfoData.SectionInfos[DllHackInfo::PDATA].Size /
                     sizeof(RUNTIME_FUNCTION));
  if (realCount > maxCount) {
    LLVM_JIT_PDB_LOG(
        Warning, ".pdata section is not big enough to store every unwind data");
  }
#undef min
  realCount = std::min(maxCount, realCount);

  fseek(dllFD, DllHackInfoData.SectionInfos[DllHackInfo::PDATA].FilePos, 0);
  fwrite(functions, sizeof(RUNTIME_FUNCTION) * realCount, 1, dllFD);

  // insert code
  if (CodeSection.mem.addr) {
    fseek(dllFD, long(codeOffInFile), 0);
    fwrite(backupMem + codeOff, CodeSection.mem.size, 1, dllFD);
  }
  if (DataRSection.mem.addr) {
    fseek(dllFD, long(dataROffInFile), 0);
    fwrite(backupMem + dataROff, DataRSection.mem.size, 1, dllFD);
  }
  if (DataRWSection.mem.addr) {
    fseek(dllFD, long(dataRWOffInFile), 0);
    fwrite(backupMem + dataRWOff, DataRWSection.mem.size, 1, dllFD);
  }

  ::free(backupMem);

  // rewrite GUID (look for RSDS in .dll, guid is just after)
  fseek(dllFD, DllHackInfoData.PdbGuidPos, 0);
  fwrite(Guid.Guid, 1, 16, dllFD);

  // rewrite PDB/DLL matching guid
  std::string guidStr(guidToStr(Guid));

  // rewrite PDB path
  fseek(dllFD, DllHackInfoData.PdbFileNamePos, 0);
  fwrite(PdbName.data(), PdbName.size() + 1, 1, dllFD);

  fclose(dllFD);

  loadDll();

  imageBase = (ULONG_PTR)DllBaseAddress;
  assert(RtlLookupFunctionEntry(
      uint64_t(reinterpret_cast<uint8_t *>(DllBaseAddress) +
               DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress),
      &imageBase, NULL));
}

void JITPDBMemoryManager::loadDll() {
  DllBaseAddress = LoadLibraryA(DllPath.c_str());
  assert(DllBaseAddress);
}

void JITPDBMemoryManager::unloadDll() {
  BOOL res = FreeLibrary((HMODULE)DllBaseAddress);
  (void)res;
  assert(res);
}

uint8_t *JITPDBMemoryManager::allocateCodeSection(uintptr_t Size,
                                                  unsigned Alignment,
                                                  unsigned SectionID,
                                                  StringRef SectionName) {
  return CodeSection.allocate(this, Size, Alignment);
}

uint8_t *JITPDBMemoryManager::allocateDataSection(uintptr_t Size,
                                                  unsigned Alignment,
                                                  unsigned SectionID,
                                                  StringRef SectionName,
                                                  bool IsReadOnly) {
  uint8_t *mem;
  if (IsReadOnly)
    mem = DataRSection.allocate(this, Size, Alignment);
  else
    mem = DataRWSection.allocate(this, Size, Alignment);

  if (SectionName == ".pdata") {
    RFDataOffset = mem - (uint8_t *)DllBaseAddress;
    RFDataSize = Size;
  } else if (SectionName == ".xdata") {
    UWDataOffset = mem - (uint8_t *)DllBaseAddress;
    UWDataSize = Size;
  }
  return mem;
}

void JITPDBMemoryManager::notifyObjectLoaded(ExecutionEngine *EE,
                                             const object::ObjectFile &Obj) {
  if (StatusValue == Status::Allocating) {
    StatusValue = Status::ObjectFileEmitted;
    if (Obj.isCOFF()) {
      if (!PDBDontEmit) {
        bool result =
            PDBBuilder.commit(getPdbPath(), Guid,
                              static_cast<object::COFFObjectFile const &>(Obj));
        if (!result) {
          StatusValue = Status::FailedToWritePDB;
          LLVM_JIT_PDB_LOG(Error, "Failed to write PDB on disk");
        }
      }
    } else {
      StatusValue = Status::COFFObjectFileRequired;
      LLVM_JIT_PDB_LOG(
          Error,
          "Emitted object file is not a pure COFF/CodeView file, no PDB can be "
          "emitted.");
    }
  }
}

bool JITPDBMemoryManager::finalizeMemory(std::string *ErrMsg) {
  if (StatusValue == Status::OK) // already finalized once
    return false;
  assert((StatusValue == Status::ObjectFileEmitted ||
          StatusValue == Status::OutOfMemory ||
          StatusValue == Status::COFFObjectFileRequired) &&
         "cannot finalize while object file not emitted/loaded yet");
  if (StatusValue == Status::OutOfMemory ||
      StatusValue == Status::MemoryNotReady)
    return true;
  reloadDll();
  if (MemoryStart !=
      (reinterpret_cast<uint8_t *>(DllBaseAddress) +
       DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress)) {
    LLVM_JIT_PDB_LOG(
        Error, "memory not available : unable to reload backing dll in same "
               "virtual space, retry required");
    StatusValue = Status::MemoryNotReady;
    return true;
  } else {
    StatusValue = Status::OK;
    return false;
  }
}

namespace {
inline uint8_t *AlignUp(uint8_t *value, size_t alignment) {
  size_t mask = alignment - 1;
  return reinterpret_cast<uint8_t *>((size_t(value) + mask) & ~mask);
}
} // namespace

uint8_t *JITPDBMemoryManager::Section::allocate(JITPDBMemoryManager *mgr,
                                                size_t size, size_t align) {
  assert(mgr->StatusValue == Status::Allocating);
  assert(cur != nullptr);
  cur = AlignUp(cur, align);
  if ((cur + size) < (((uint8_t *)mem.addr) + mem.size)) {
    uint8_t *ptr = cur;
    cur = ptr + size;
    return ptr;
  } else {
    mgr->StatusValue = Status::OutOfMemory;
    return nullptr;
  }
}

} // namespace llvm
