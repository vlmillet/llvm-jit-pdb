// license [
// This file is part of the LLVMJITPDB project. Copyright 2020 Vivien Millet.
// Distributed under the Apache License 2.0. Text available here at
// https://github.com/vlmillet/llvmjitpdb
// ]

#pragma once

#pragma warning(push, 0)
#include <llvm/DebugInfo/CodeView/GUID.h>
#include <llvm/ExecutionEngine/RTDyldMemoryManager.h>
#pragma warning(pop)
#include "JITPDBFileBuilder.h"

namespace llvm {
class JITPDBMemoryManager : public RTDyldMemoryManager {
public:
  enum class Status {
    Allocating,
    ObjectFileEmitted,
    InvalidObjectFileType,
    OK,
    MemoryNotReady,
    OutOfMemory,
  };

  JITPDBMemoryManager(StringRef PdbPath,
                      std::function<void(void *)> NotifyModuleEmittedCB =
                          std::function<void(void *)>());
  ~JITPDBMemoryManager();

  codeview::GUID const &getGuid() const { return Guid; }
  std::string const &getPdbPath() const { return PdbPath; }
  std::string const &getDllPath() const { return DllPath; }
  std::string const &getOutputPath() const { return OutputPath; }

  JITPDBMemoryManager &setVerbose(bool Verbose) { this->Verbose = Verbose; }

  pdb::JITPDBFileBuilder &getPDBFileBuilder() { return PDBBuilder; }
  pdb::JITPDBFileBuilder const &getPDBFileBuilder() const { return PDBBuilder; }

  Status getStatus() const { return StatusValue; }
  Status finalize();

protected:
  uint8_t *allocateCodeSection(uintptr_t Size, unsigned Alignment,
                               unsigned SectionID,
                               StringRef SectionName) override;
  uint8_t *allocateDataSection(uintptr_t Size, unsigned Alignment,
                               unsigned SectionID, StringRef SectionName,
                               bool IsReadOnly) override;
  void notifyObjectLoaded(ExecutionEngine *EE,
                          const object::ObjectFile &) override;
  bool finalizeMemory(std::string *) override;

private:
  void createDll();
  void loadDll();
  void reloadDll();
  void unloadDll();

private:
  struct Section {
    struct MemBlock {
      uint8_t *addr;
      size_t size;
    };
    MemBlock mem = MemBlock{0, 0};
    uint8_t *cur = nullptr;

    uint8_t *allocate(JITPDBMemoryManager *mgr, size_t size, size_t align);
  };
  struct DllHackInfo {
    enum SectionID { TEXT, RDATA, PDATA, XDATA, SECTION_COUNT };

    int SubSectionParent[SECTION_COUNT] = {-1, -1, -1, 1};

    struct SectionInfo {
      int HeaderPos;
      int VirtualAddress;
      int Size;
      int FilePos;
    } SectionInfos[SECTION_COUNT];

    int TimeStampPos = 0;
    int PdbFileNamePos = 0;
    int PdbGuidPos = 0;

  } DllHackInfoData;
  Section CodeSection;
  Section DataRSection;
  Section DataRWSection;
  uint64_t RFDataOffset = 0;
  uint64_t RFDataSize = 0;
  uint64_t UWDataOffset = 0;
  uint64_t UWDataSize = 0;
  void *DllBaseAddress = nullptr;
  uint8_t *MemoryStart = nullptr;
  size_t MemorySize = 0;
  codeview::GUID Guid;
  pdb::JITPDBFileBuilder PDBBuilder;
  std::string PdbPath;
  std::string PdbName;
  std::string OutputPath;
  std::string DllPath;
  std::function<void(void *)> NotifyModuleEmitted;
  Status StatusValue = Status::Allocating;
  bool Verbose = false;
};

} // namespace llvm
