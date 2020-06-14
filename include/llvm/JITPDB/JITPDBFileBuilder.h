// license [
// This file is part of the LLVMJITPDB project. Copyright 2020 Vivien Millet.
// Distributed under the Apache License 2.0. Text available here at
// https://github.com/vlmillet/llvmjitpdb
// ]

#pragma once

#if !defined(_WIN32) || !defined(_MSC_VER)
#error JITPDB is only available on windows and Visual Studio
#endif

#pragma warning(push, 0)
#include <llvm/ADT/DenseMap.h>
#include <llvm/DebugInfo/CodeView/GUID.h>
#include <llvm/ExecutionEngine/RuntimeDyld.h>
#pragma warning(pop)

namespace llvm {
namespace object {
class COFFObjectFile;
}
namespace pdb {
class PDBFile;
}
} // namespace llvm

namespace llvm {
class JITPDBMemoryManager;
namespace pdb {
class JITPDBFileBuilder {
public:
  bool commit(StringRef PdbPath, codeview::GUID Guid,
              object::COFFObjectFile const &ObjFile,
              StringRef PdbTplPath = StringRef());
  void addNatvisFile(StringRef _filePath);
  void addNatvisBuffer(StringRef _filePath,
                       std::unique_ptr<MemoryBuffer> _fileData);

private:
  bool EmitPDBImpl(StringRef PdbPath, codeview::GUID Guid,
                   object::COFFObjectFile const &ObjFile, uint64_t ImageBase,
                   StringRef PdbTplPath);

private:
  SmallVector<std::pair<std::string, std::unique_ptr<MemoryBuffer>>, 1>
      NatvisFiles;
};
} // namespace pdb
} // namespace llvm
