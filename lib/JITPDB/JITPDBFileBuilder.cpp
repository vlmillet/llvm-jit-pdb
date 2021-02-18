// license [
// This file is part of the LLVMJITPDB project. Copyright 2020 Vivien Millet.
// Distributed under the Apache License 2.0. Text available here at
// https://github.com/vlmillet/llvmjitpdb
// ]

#include <llvm/JITPDB/JITPDBFileBuilder.h>
#include <llvm/JITPDB/JITPDBMemoryManager.h>

#pragma warning(push, 0)

#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/BitVector.h>
#include <llvm/DebugInfo/CodeView/DebugFrameDataSubsection.h>
#include <llvm/DebugInfo/CodeView/GlobalTypeTableBuilder.h>
#include <llvm/DebugInfo/CodeView/MergingTypeTableBuilder.h>
#include <llvm/DebugInfo/CodeView/RecordName.h>
#include <llvm/DebugInfo/CodeView/StringsAndChecksums.h>
#include <llvm/DebugInfo/CodeView/SymbolDeserializer.h>
#include <llvm/DebugInfo/CodeView/SymbolSerializer.h>
#include <llvm/DebugInfo/CodeView/TypeIndexDiscovery.h>
#include <llvm/DebugInfo/CodeView/TypeStreamMerger.h>
#include <llvm/DebugInfo/MSF/MSFBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiStream.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/ISectionContribVisitor.h>
#include <llvm/DebugInfo/PDB/Native/InfoStream.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/ModuleDebugStream.h>
#include <llvm/DebugInfo/PDB/Native/NativeSession.h>
#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include <llvm/DebugInfo/PDB/Native/PDBStringTableBuilder.h>
#include <llvm/DebugInfo/PDB/Native/PublicsStream.h>
#include <llvm/DebugInfo/PDB/Native/RawError.h>
#include <llvm/DebugInfo/PDB/Native/SymbolStream.h>
#include <llvm/DebugInfo/PDB/Native/TpiHashing.h>
#include <llvm/DebugInfo/PDB/Native/TpiStream.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/PDB.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/BinaryStream.h>
#include <llvm/Support/BinaryStreamWriter.h>
#include <llvm/Support/CRC.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/xxhash.h>
#include <map>
#include <windows.h>

#pragma warning(pop)

#define LLVM_JIT_PDB_ADD_GLOBALS 1
#define LLVM_JIT_DUMP_WITH_PDBUTIL_ENABLED 0
#define LLVM_JIT_TEXT_SECTION_VIRTUAL_ADDRESS 0x1000

namespace {
enum class LogKind { Information, Warning, Error };
}

#define LLVM_JIT_PDB_LOG(Kind, ...)                                            \
  if (LogKind::Kind == LogKind::Warning || LogKind::Kind == LogKind::Error) {  \
    printf(#Kind ": " __VA_ARGS__);                                            \
    printf("\n");                                                              \
  }

extern char JITPDB_PDB[];
extern unsigned long long JITPDB_PDB_SIZE;

namespace llvm {
using namespace codeview;
using namespace pdb;
namespace {
inline bool symbolOpensScope(SymbolKind Kind) {
  switch (Kind) {
  case SymbolKind::S_GPROC32:
  case SymbolKind::S_LPROC32:
  case SymbolKind::S_LPROC32_ID:
  case SymbolKind::S_GPROC32_ID:
  case SymbolKind::S_BLOCK32:
  case SymbolKind::S_SEPCODE:
  case SymbolKind::S_THUNK32:
  case SymbolKind::S_INLINESITE:
  case SymbolKind::S_INLINESITE2:
    return true;
  default:
    break;
  }
  return false;
}

/// Return true if this ssymbol ends a scope.
inline bool symbolEndsScope(SymbolKind Kind) {
  switch (Kind) {
  case SymbolKind::S_END:
  case SymbolKind::S_PROC_ID_END:
  case SymbolKind::S_INLINESITE_END:
    return true;
  default:
    break;
  }
  return false;
}

Expected<ModuleDebugStreamRef> getModuleDebugStream(PDBFile &File,
                                                    uint32_t Index) {
  ExitOnError Err("Unexpected error: ");

  DbiStream &Dbi = Err(File.getPDBDbiStream());
  const auto &Modules = Dbi.modules();
  auto Modi = Modules.getModuleDescriptor(Index);

  uint16_t ModiStream = Modi.getModuleStreamIndex();
  if (ModiStream == kInvalidStreamIndex)
    return make_error<RawError>(raw_error_code::no_stream,
                                "Module stream not_ present");

  auto ModStreamData = File.createIndexedStream(ModiStream);

  ModuleDebugStreamRef ModS(Modi, std::move(ModStreamData));
  if (auto EC = ModS.reload())
    return make_error<RawError>(raw_error_code::corrupt_file,
                                "Invalid module stream");

  return std::move(ModS);
}

Error loadSectionHeaders(PDBFile &File, DbgHeaderType Type,
                         ArrayRef<uint8_t> &Buffer,
                         ArrayRef<object::coff_section> &Sections) {
  if (!File.hasPDBDbiStream())
    return make_error<StringError>(
        "Section headers require a DBI Stream, which could not_ be loaded",
        inconvertibleErrorCode());

  auto &Dbi = cantFail(File.getPDBDbiStream());
  uint32_t SI = Dbi.getDebugStreamIndex(Type);

  if (SI == kInvalidStreamIndex)
    return make_error<StringError>(
        "PDB does not_ contain the requested image section header type",
        inconvertibleErrorCode());

  auto Stream = File.createIndexedStream(SI);
  if (!Stream)
    return make_error<StringError>("Could not_ load the required stream data",
                                   inconvertibleErrorCode());

  BinaryStreamReader Reader(*Stream);
  uint32_t NumHeaders = Stream->getLength() / sizeof(object::coff_section);
  cantFail(Reader.readArray(Sections, NumHeaders));
  Buffer = ArrayRef<uint8_t>((uint8_t *)Sections.data(), Stream->getLength());
  return Error::success();
}

void initializeStringsAndChecksums(DebugSubsectionArray const &Sections,
                                   codeview::StringsAndChecksums &SC,
                                   PDBStringTable const &GlobalStringTable) {
  // String Table and_ Checksums subsections don't use the allocator.
  BumpPtrAllocator Allocator;

  // It's possible for checksums and_ strings to even appear in different
  // debug$S sections, so we have to make this a stateful function that can
  // build up the strings and_ checksums field over multiple iterations.

  // File Checksums require the string table, but may become before it, so we
  // have to scan for strings first, then scan for checksums again from the
  // beginning.
  if (!SC.hasStrings()) {
    for (const DebugSubsectionRecord &SS : Sections) {
      if (SS.kind() != DebugSubsectionKind::StringTable)
        continue;

      auto Result = std::make_shared<DebugStringTableSubsection>();

      BinaryStreamReader reader(SS.getRecordData());
      while (reader.bytesRemaining()) {
        StringRef str;
        reader.readCString(str);
        Result->insert(str);
      }

      SC.setStrings(Result);
      break;
    }
  }

  if (SC.hasStrings() && !SC.hasChecksums()) {
    for (const auto &SS : Sections) {
      if (SS.kind() != DebugSubsectionKind::FileChecksums)
        continue;

      auto Result = std::make_shared<DebugChecksumsSubsection>(*SC.strings());

      DebugChecksumsSubsectionRef csref;
      BinaryStreamReader reader(SS.getRecordData());
      csref.initialize(reader);
      for (auto fcs : csref.getArray()) {
        StringRef FileName = cantFail(
            GlobalStringTable.getStringTable().getString(fcs.FileNameOffset));
        Result->addChecksum(FileName, fcs.Kind, fcs.Checksum);
      }

      SC.setChecksums(Result);
      break;
    }
  }
}

void addCommonLinkerModuleSymbols(StringRef PdbPath,
                                  pdb::DbiModuleDescriptorBuilder &Mod,
                                  BumpPtrAllocator &Allocator) {
  ObjNameSym ONS(SymbolRecordKind::ObjNameSym);
  Compile3Sym CS(SymbolRecordKind::Compile3Sym);
  EnvBlockSym EBS(SymbolRecordKind::EnvBlockSym);

  ONS.Name = "* Linker *";
  ONS.Signature = 0;

#if defined(_M_X64)
  CS.Machine = codeview::CPUType::X64;
#else
  CS.Machine = codeview::CPUType::Intel80386;
#endif

  // Interestingly, if we set the string to 0.0.0.0, then when trying to view
  // local variables WinDbg emits an error that private symbols are not_
  // present. By setting this to a valid MSVC linker version string, local
  // variables are displayed properly.   As such, even though it is not_
  // representative of LLVM's version information, we need this for
  // compatibility.
  CS.Flags = CompileSym3Flags::None;
  CS.VersionBackendBuild = 25019;
  CS.VersionBackendMajor = 14;
  CS.VersionBackendMinor = 10;
  CS.VersionBackendQFE = 0;

  // MSVC also sets the frontend to 0.0.0.0 since this is specifically for the
  // linker module (which is by definition a backend), so we don't need to do
  // anything here.  Also, it seems we can use "LLVM Linker" for the linker name
  // without any problems.  Only the backend version has to be hardcoded to a
  // magic number.
  CS.VersionFrontendBuild = 0;
  CS.VersionFrontendMajor = 0;
  CS.VersionFrontendMinor = 0;
  CS.VersionFrontendQFE = 0;
  CS.Version = "LLVM Linker";
  CS.setLanguage(SourceLanguage::Link);

  EBS.Fields.push_back("cwd");
  SmallString<260> cwd;
  sys::fs::current_path(cwd);
  EBS.Fields.push_back(cwd);
  EBS.Fields.push_back("exe");
  char buffer[MAX_PATH];
  GetModuleFileNameA(NULL, buffer, MAX_PATH);
  SmallString<64> exe = buffer;
  EBS.Fields.push_back(exe);
  EBS.Fields.push_back("pdb");
  EBS.Fields.push_back(PdbPath);
  EBS.Fields.push_back("cmd");
  EBS.Fields.push_back("\"\"");
  Mod.addSymbol(codeview::SymbolSerializer::writeOneSymbol(
      ONS, Allocator, CodeViewContainer::Pdb));
  Mod.addSymbol(codeview::SymbolSerializer::writeOneSymbol(
      CS, Allocator, CodeViewContainer::Pdb));
  Mod.addSymbol(codeview::SymbolSerializer::writeOneSymbol(
      EBS, Allocator, CodeViewContainer::Pdb));
}

void addLinkerModuleSectionSymbol(pdb::DbiModuleDescriptorBuilder &Mod,
                                  BumpPtrAllocator &Allocator,
                                  size_t SectionIndex) {
  SectionSym Sym(SymbolRecordKind::SectionSym);
  Sym.Alignment = 12; // 2^12 = 4KB
  Sym.Characteristics = 0;
  Sym.Length = 0;
  Sym.Name = "";
  Sym.Rva = 0;
  Sym.SectionNumber = SectionIndex;
  Mod.addSymbol(codeview::SymbolSerializer::writeOneSymbol(
      Sym, Allocator, CodeViewContainer::Pdb));
}

PDBFile *LoadCppEmbeddedPDB(std::unique_ptr<IPDBSession> &Session,
                            StringRef PdbTplPath) {

  if (PdbTplPath.empty()) {
    auto buffer = MemoryBuffer::getMemBuffer(
        StringRef(JITPDB_PDB, JITPDB_PDB_SIZE), "", false);
    if (auto E = pdb::NativeSession::createFromPdb(std::move(buffer), Session))
      return nullptr;
  } else {
    auto errorOrBuffer = MemoryBuffer::getFile(PdbTplPath);
    if (!errorOrBuffer)
      return nullptr;
    if (auto E = pdb::NativeSession::createFromPdb(std::move(*errorOrBuffer),
                                                   Session))
      return nullptr;
  }
  NativeSession *NS = static_cast<NativeSession *>(Session.get());
  return &NS->getPDBFile();
}

void add16(uint8_t *P, int16_t V) {
  support::endian::write16le(P, support::endian::read16le(P) + V);
}
void add32(uint8_t *P, int32_t V) {
  support::endian::write32le(P, support::endian::read32le(P) + V);
}
void add64(uint8_t *P, int64_t V) {
  support::endian::write64le(P, support::endian::read64le(P) + V);
}
void or16(uint8_t *P, uint16_t V) {
  support::endian::write16le(P, support::endian::read16le(P) | V);
}
void or32(uint8_t *P, uint32_t V) {
  support::endian::write32le(P, support::endian::read32le(P) | V);
}

void applySecIdx(uint8_t *Off) {
  // Absolute symbol doesn't have section index, but section index relocation
  // against absolute symbol should be resolved to one plus the last output
  // section index. This is required for compatibility with MSVC.
  add16(Off, 1);
}
void applySecRel(uint8_t *Off, uint64_t S) { add32(Off, S); }
void applyRelX64(uint64_t ImageBase, uint8_t *Off, uint16_t Type, uint64_t S,
                 uint64_t P) {
  switch (Type) {
  case IMAGE_REL_AMD64_ADDR32:
    add32(Off, S + ImageBase);
    break;
  case IMAGE_REL_AMD64_ADDR64:
    add64(Off, S + ImageBase);
    break;
  case IMAGE_REL_AMD64_ADDR32NB:
    add32(Off, S);
    break;
  case IMAGE_REL_AMD64_REL32:
    add32(Off, S - P - 4);
    break;
  case IMAGE_REL_AMD64_REL32_1:
    add32(Off, S - P - 5);
    break;
  case IMAGE_REL_AMD64_REL32_2:
    add32(Off, S - P - 6);
    break;
  case IMAGE_REL_AMD64_REL32_3:
    add32(Off, S - P - 7);
    break;
  case IMAGE_REL_AMD64_REL32_4:
    add32(Off, S - P - 8);
    break;
  case IMAGE_REL_AMD64_REL32_5:
    add32(Off, S - P - 9);
    break;
  case IMAGE_REL_AMD64_SECTION:
    applySecIdx(Off);
    break;
  case IMAGE_REL_AMD64_SECREL:
    applySecRel(Off, S);
    break;
  default:
    printf("%s", ("unsupported relocation type 0x" + Twine::utohexstr(Type))
                     .str()
                     .c_str());
  }
}

void writeTo(object::COFFObjectFile const &ObjFile,
             object::coff_section const &Header, uint8_t *Buf,
             ArrayRef<object::COFFSymbolRef> RelocTargets) {
  if (!Header.SizeOfRawData)
    return;
  // Copy section contents from source object file to output file.
  ArrayRef<uint8_t> A;
  ObjFile.getSectionContents(&Header, A);
  if (!A.empty())
    memcpy(Buf /*+ OutputSectionOff*/, A.data(), A.size());

  // Apply relocations.
  size_t InputSize = Header.SizeOfRawData;
  for (size_t I = 0, E = RelocTargets.size(); I < E; I++) {
    const object::coff_relocation &Rel = ObjFile.getRelocations(&Header)[I];

    // Check for an invalid relocation offset. This check isn't perfect, because
    // we don't have the relocation size, which is only known after checking the
    // machine and_ relocation type. As a result, a relocation may overwrite the
    // beginning of the following input section.
    if (Rel.VirtualAddress >= InputSize) {
      printf("relocation points beyond the end of its parent section");
      continue;
    }

    uint8_t *Off = Buf + /*OutputSectionOff + */ Rel.VirtualAddress;

    // Use the potentially remapped Symbol instead of the one that the
    // relocation points to.
    object::COFFSymbolRef Sym(RelocTargets[I]);

    uint64_t S = Sym.getValue();

    // Compute the RVA of the relocation for relative relocations.
    uint64_t P = Rel.VirtualAddress;

    applyRelX64(0, Off, Rel.Type, S, P);
  }
}

void readRelocTargets(object::COFFObjectFile const &ObjFile,
                      object::coff_section const &Header,
                      std::vector<object::COFFSymbolRef> &RelocTargets) {
  RelocTargets.reserve(Header.NumberOfRelocations);
  auto Relocs(ObjFile.getRelocations(&Header));
  for (const object::coff_relocation &Rel : Relocs)
    RelocTargets.push_back(*ObjFile.getSymbol(Rel.SymbolTableIndex));
}
// Allocate memory for a .debug$S / .debug$F section and_ relocate it.
ArrayRef<uint8_t> relocateDebugChunk(object::COFFObjectFile const &ObjFile,
                                     BumpPtrAllocator &Alloc,
                                     object::coff_section const &Header) {
  uint8_t *Buffer = Alloc.Allocate<uint8_t>(Header.SizeOfRawData);
  std::vector<object::COFFSymbolRef> relocs;
  readRelocTargets(ObjFile, Header, relocs);
  writeTo(ObjFile, Header, Buffer, relocs);
  return makeArrayRef(Buffer, Header.SizeOfRawData);
}

pdb::SectionContrib createSectionContrib(object::COFFObjectFile const &ObjFile,
                                         object::coff_section const *Header,
                                         uint16_t SecIdx, uint32_t Modi) {
  pdb::SectionContrib SC;
  memset(&SC, 0, sizeof(SC));
  SC.ISect = SecIdx;
  auto secIt = ObjFile.section_begin();
  std::advance(secIt, SecIdx);
  SC.Off = Header->VirtualAddress;
  SC.Size = Header->SizeOfRawData;
  SC.Characteristics = Header->Characteristics;
  SC.Imod = Modi;
  ArrayRef<uint8_t> Contents;
  ObjFile.getSectionContents(Header, Contents);
  JamCRC CRC(0);
  ArrayRef<uint8_t> CharContents = makeArrayRef(
      reinterpret_cast<const uint8_t *>(Contents.data()), Contents.size());
  CRC.update(CharContents);
  SC.DataCrc = CRC.getCRC();

  SC.RelocCrc = 0; // FIXME

  return SC;
}

ArrayRef<uint8_t> consumeDebugMagic(ArrayRef<uint8_t> Data, StringRef SecName) {
  // First 4 bytes are section magic.
  assert(Data.size() >= 4);
  assert(support::endian::read32le(Data.data()) == COFF::DEBUG_SECTION_MAGIC);
  return Data.slice(4);
}

void InsertObjFileSectionHeaders(object::COFFObjectFile const &ObjFile,
                                 std::vector<object::coff_section> &AllSections,
                                 size_t &DebugSIndexSection) {
  size_t sectionIndex = 0;
  size_t startVirtualAddress = LLVM_JIT_TEXT_SECTION_VIRTUAL_ADDRESS;
  for (const object::SectionRef &Section : ObjFile.sections()) {
    StringRef SectionName;
    if (auto E = Section.getName()) {
      SectionName = *E;
    } else
      continue;
    auto sec = ObjFile.getCOFFSection(Section);
    if (".debug$S" == SectionName) {
      DebugSIndexSection = AllSections.size();
    } else if (".debug$T" == SectionName) {
      ArrayRef<uint8_t> Contents;
      ObjFile.getSectionContents(sec, Contents);
      Contents = consumeDebugMagic(Contents, SectionName);
    } else {
      ArrayRef<uint8_t> Contents;
      ObjFile.getSectionContents(sec, Contents);
      AllSections.push_back(*sec);
      AllSections.back().VirtualAddress = startVirtualAddress; //
      AllSections.back().VirtualSize = AllSections.back().SizeOfRawData;
      startVirtualAddress += AllSections.back().SizeOfRawData;
      AllSections.back().NumberOfRelocations = 0;
      ++sectionIndex;
    }
  }
}

struct ScopeRecord {
  ulittle32_t PtrParent;
  ulittle32_t PtrEnd;
};

struct SymbolScope {
  ScopeRecord *OpeningRecord;
  uint32_t ScopeOffset;
};

SymbolKind symbolKind(ArrayRef<uint8_t> RecordData) {
  const RecordPrefix *Prefix =
      reinterpret_cast<const RecordPrefix *>(RecordData.data());
  return static_cast<SymbolKind>(uint16_t(Prefix->RecordKind));
}

void scopeStackOpen(SmallVectorImpl<SymbolScope> &Stack, uint32_t CurOffset,
                    CVSymbol &Sym) {
  assert(symbolOpensScope(Sym.kind()));
  SymbolScope S;
  S.ScopeOffset = CurOffset;
  S.OpeningRecord = const_cast<ScopeRecord *>(
      reinterpret_cast<const ScopeRecord *>(Sym.content().data()));
  S.OpeningRecord->PtrParent = Stack.empty() ? 0 : Stack.back().ScopeOffset;
  Stack.push_back(S);
}

void scopeStackClose(SmallVectorImpl<SymbolScope> &Stack, uint32_t CurOffset) {
  if (Stack.empty()) {
    printf("symbol scopes are not_ balanced in jit");
    return;
  }
  SymbolScope S = Stack.pop_back_val();
  S.OpeningRecord->PtrEnd = CurOffset;
}

/// MSVC translates S_PROC_ID_END to S_END, and_ S_[LG]PROC32_ID to S_[LG]PROC32
void translateIdSymbols(MutableArrayRef<uint8_t> &RecordData,
                        TypeCollection &IDTable) {
  RecordPrefix *Prefix = reinterpret_cast<RecordPrefix *>(RecordData.data());

  SymbolKind Kind = symbolKind(RecordData);

  if (Kind == SymbolKind::S_PROC_ID_END) {
    Prefix->RecordKind = SymbolKind::S_END;
    return;
  }

  // In an object file, GPROC32_ID has an embedded reference which refers to the
  // single object file type index namespace.  This has already been translated
  // to the PDB file's ID stream index space, but we need to convert this to a
  // symbol that refers to the type stream index space.  So we remap again from
  // ID index space to type index space.
  if (Kind == SymbolKind::S_GPROC32_ID || Kind == SymbolKind::S_LPROC32_ID) {
    SmallVector<TiReference, 1> Refs;
    auto Content = RecordData.drop_front(sizeof(RecordPrefix));

    CVSymbol Sym(Prefix, sizeof(RecordPrefix));
    discoverTypeIndicesInSymbol(Sym, Refs);
    assert(Refs.size() == 1);
    assert(Refs.front().Count == 1);

    TypeIndex *TI =
        reinterpret_cast<TypeIndex *>(Content.data() + Refs[0].Offset);
    // `TI` is the index of a FuncIdRecord or_ MemberFuncIdRecord which lives in
    // the IPI stream, whose `FunctionType` member refers to the TPI stream.
    // Note that LF_FUNC_ID and_ LF_MEMFUNC_ID have the same record layout, and_
    // in both cases we just need the second type index.
    if (!TI->isSimple() && !TI->isNoneType()) {
      CVType FuncIdData = IDTable.getType(*TI);
      SmallVector<TypeIndex, 2> Indices;
      discoverTypeIndices(FuncIdData, Indices);
      assert(Indices.size() == 2);
      *TI = Indices[1];
    }

    Kind = (Kind == SymbolKind::S_GPROC32_ID) ? SymbolKind::S_GPROC32
                                              : SymbolKind::S_LPROC32;
    Prefix->RecordKind = uint16_t(Kind);
  }
}

/// Copy the symbol record. In a PDB, symbol records must be 4 byte aligned.
/// The object file may not_ be aligned.
MutableArrayRef<uint8_t>
copyAndAlignSymbol(const CVSymbol &Sym, MutableArrayRef<uint8_t> &AlignedMem) {
  size_t Size = alignTo(Sym.length(), alignOf(CodeViewContainer::Pdb));
  assert(Size >= 4 && "record too short");
  assert(Size <= MaxRecordLength && "record too long");
  assert(AlignedMem.size() >= Size && "didn't preallocate enough");

  // Copy the symbol record and_ zero out any padding bytes.
  MutableArrayRef<uint8_t> NewData = AlignedMem.take_front(Size);
  AlignedMem = AlignedMem.drop_front(Size);
  memcpy(NewData.data(), Sym.data().data(), Sym.length());
  memset(NewData.data() + Sym.length(), 0, Size - Sym.length());

  // Update the record prefix length. It should point to the beginning of the
  // next record.
  auto *Prefix = reinterpret_cast<RecordPrefix *>(NewData.data());
  Prefix->RecordLen = Size - 2;
  return NewData;
}

bool symbolGoesInModuleStream(const CVSymbol &Sym, bool IsGlobalScope) {
  switch (Sym.kind()) {
  case SymbolKind::S_GDATA32:
  case SymbolKind::S_CONSTANT:
    // We really should not_ be seeing S_PROCREF and_ S_LPROCREF in the first
    // place since they are synthesized by the linker in response to S_GPROC32
    // and_ S_LPROC32, but if we do see them, don't put them in the module
    // stream I guess.
  case SymbolKind::S_PROCREF:
  case SymbolKind::S_LPROCREF:
    return false;
    // S_UDT records go in the module stream if it is not_ a global S_UDT.
  case SymbolKind::S_UDT:
    return !IsGlobalScope;
    // S_GDATA32 does not_ go in the module stream, but S_LDATA32 does.
  case SymbolKind::S_LDATA32:
  default:
    return true;
  }
}

bool symbolGoesInGlobalsStream(const CVSymbol &Sym, bool IsGlobalScope) {
  switch (Sym.kind()) {
  case SymbolKind::S_CONSTANT:
  case SymbolKind::S_GDATA32:
    // S_LDATA32 goes in both the module stream and_ the globals stream.
  case SymbolKind::S_LDATA32:
  case SymbolKind::S_GPROC32:
  case SymbolKind::S_LPROC32:
    // We really should not_ be seeing S_PROCREF and_ S_LPROCREF in the first
    // place since they are synthesized by the linker in response to S_GPROC32
    // and_ S_LPROC32, but if we do see them, copy them straight through.
  case SymbolKind::S_PROCREF:
  case SymbolKind::S_LPROCREF:
    return true;
    // S_UDT records go in the globals stream if it is a global S_UDT.
  case SymbolKind::S_UDT:
    return IsGlobalScope;
  default:
    return false;
  }
}

void addGlobalSymbol(pdb::GSIStreamBuilder &Builder, uint16_t ModIndex,
                     unsigned SymOffset, const CVSymbol &Sym) {
  switch (Sym.kind()) {
  case SymbolKind::S_CONSTANT:
  case SymbolKind::S_UDT:
  case SymbolKind::S_GDATA32:
  case SymbolKind::S_LDATA32:
  case SymbolKind::S_PROCREF:
  case SymbolKind::S_LPROCREF:
    Builder.addGlobalSymbol(Sym);
    break;
  case SymbolKind::S_GPROC32:
  case SymbolKind::S_LPROC32: {
    SymbolRecordKind K = SymbolRecordKind::ProcRefSym;
    if (Sym.kind() == SymbolKind::S_LPROC32)
      K = SymbolRecordKind::LocalProcRef;
    ProcRefSym PS(K);
    PS.Module = ModIndex;
    // For some reason, MSVC seems to add one to this value.
    ++PS.Module;
    PS.Name = getSymbolName(Sym);
    PS.SumName = 0;
    PS.SymOffset = SymOffset;
    Builder.addGlobalSymbol(PS);
    break;
  }
  default:
    llvm_unreachable("Invalid symbol kind!");
  }
}

/// Map from type index and_ item index in a type server PDB to the
/// corresponding index in the destination PDB.
struct CVIndexMap {
  SmallVector<TypeIndex, 0> TPIMap;
  SmallVector<TypeIndex, 0> IPIMap;
  bool IsTypeServerMap = false;
  bool IsPrecompiledTypeMap = false;
};

bool remapTypeIndex(TypeIndex &TI, ArrayRef<TypeIndex> TypeIndexMap) {
  if (TI.isSimple())
    return true;
  if (TI.toArrayIndex() >= TypeIndexMap.size())
    return false;
  TI = TypeIndexMap[TI.toArrayIndex()];
  return true;
}

void remapTypesInSymbolRecord(SymbolKind SymKind,
                              MutableArrayRef<uint8_t> RecordBytes,
                              const CVIndexMap &IndexMap,
                              ArrayRef<TiReference> TypeRefs) {
  MutableArrayRef<uint8_t> Contents =
      RecordBytes.drop_front(sizeof(RecordPrefix));
  for (const TiReference &Ref : TypeRefs) {
    unsigned ByteSize = Ref.Count * sizeof(TypeIndex);
    if (Contents.size() < Ref.Offset + ByteSize)
      assert(false);

    // This can be an item index or_ a type index. Choose the appropriate map.
    ArrayRef<TypeIndex> TypeOrItemMap = IndexMap.TPIMap;
    bool IsItemIndex = Ref.Kind == TiRefKind::IndexRef;
    if (IsItemIndex && IndexMap.IsTypeServerMap)
      TypeOrItemMap = IndexMap.IPIMap;

    MutableArrayRef<TypeIndex> TIs(
        reinterpret_cast<TypeIndex *>(Contents.data() + Ref.Offset), Ref.Count);
    for (TypeIndex &TI : TIs) {
      if (!remapTypeIndex(TI, TypeOrItemMap)) {
        //  "ignoring symbol record of kind 0x" + utohexstr(SymKind) + " in " +
        //  File->getName() + " with bad " + (IsItemIndex ? "item" : "type") +
        //  " index 0x" + utohexstr(TI.getIndex()));
        TI = TypeIndex(SimpleTypeKind::NotTranslated);
        continue;
      }
    }
  }
}

void recordStringTableReferences(SymbolKind Kind,
                                 MutableArrayRef<uint8_t> Contents) {
  // For now we only handle S_FILESTATIC, but we may need the same logic for
  // S_DEFRANGE and_ S_DEFRANGE_SUBFIELD.  However, I cannot seem to generate
  // any PDBs that contain these types of records, so because of the uncertainty
  // they are omitted here until we can prove that it's necessary.
  switch (Kind) {
  case SymbolKind::S_FILESTATIC:
    // FileStaticSym::ModFileOffset
    assert(false);
    // recordStringTableReferenceAtOffset(Contents, 8, StrTableRefs);
    break;
  case SymbolKind::S_DEFRANGE:
  case SymbolKind::S_DEFRANGE_SUBFIELD:
    //         log("Not fixing up string table reference in S_DEFRANGE / "
    //             "S_DEFRANGE_SUBFIELD record");
    break;
  default:
    break;
  }
}

bool mergeSymbolRecords(PDBFileBuilder &pdbBuilder,
                        DbiModuleDescriptorBuilder &modBuilder,
                        TypeCollection &IDTable, BinaryStreamRef SymData,
                        CVIndexMap &IndexMap, BumpPtrAllocator &Allocator) {
  ArrayRef<uint8_t> SymsBuffer;
  cantFail(SymData.readBytes(0, SymData.getLength(), SymsBuffer));
  SmallVector<SymbolScope, 4> Scopes;

  // Iterate every symbol to check if any need to be realigned, and_ if so, how
  // much space we need to allocate for them.
  bool NeedsRealignment = false;
  unsigned TotalRealignedSize = 0;
  auto EC =
      forEachCodeViewRecord<CVSymbol>(SymsBuffer, [&](CVSymbol Sym) -> Error {
        unsigned RealignedSize =
            alignTo(Sym.length(), alignOf(CodeViewContainer::Pdb));
        NeedsRealignment |= RealignedSize != Sym.length();
        TotalRealignedSize += RealignedSize;
        return Error::success();
      });

  // If any of the symbol record lengths was corrupt, ignore them all, warn
  // about it, and_ move on.
  if (EC) {
    return false;
  }

  // If any symbol needed realignment, allocate enough contiguous memory for
  // them all. Typically symbol subsections are small enough that this will not_
  // cause fragmentation.
  MutableArrayRef<uint8_t> AlignedSymbolMem;
  if (NeedsRealignment) {
    void *AlignedData =
        Allocator.Allocate(TotalRealignedSize, alignOf(CodeViewContainer::Pdb));
    AlignedSymbolMem = makeMutableArrayRef(
        reinterpret_cast<uint8_t *>(AlignedData), TotalRealignedSize);
  }

  // Iterate again, this time doing the real work.
  unsigned CurSymOffset = modBuilder.getNextSymbolOffset();
  ArrayRef<uint8_t> BulkSymbols;
  cantFail(
      forEachCodeViewRecord<CVSymbol>(SymsBuffer, [&](CVSymbol Sym) -> Error {
        // Align the record if required.
        MutableArrayRef<uint8_t> RecordBytes;
        if (NeedsRealignment) {
          RecordBytes = copyAndAlignSymbol(Sym, AlignedSymbolMem);
          Sym = CVSymbol(RecordBytes);
        } else {
          // Otherwise, we can actually mutate the symbol directly, since we
          // copied it to apply relocations.
          RecordBytes = makeMutableArrayRef(
              const_cast<uint8_t *>(Sym.data().data()), Sym.length());
        }

        // Discover type index references in the record. Skip it if we don't
        // know where they are.
        SmallVector<TiReference, 32> TypeRefs;
        if (!discoverTypeIndicesInSymbol(Sym, TypeRefs)) {
          printf("ignoring unknown symbol record with kind 0x%s",
                 utohexstr(Sym.kind()).c_str());
          return Error::success();
        }

        // Re-map all the type index references.
        remapTypesInSymbolRecord(Sym.kind(), RecordBytes, IndexMap, TypeRefs);

        // An object file may have S_xxx_ID symbols, but these get converted to
        // "real" symbols in a PDB.
        translateIdSymbols(RecordBytes, IDTable);
        Sym = CVSymbol(RecordBytes);

        // If this record refers to an offset in the object file's string table,
        // add that item to the global PDB string table and_ re-write the index.
        recordStringTableReferences(Sym.kind(),
                                    RecordBytes /*, StringTableRefs*/);

        // Fill in "Parent" and_ "End" fields by maintaining a stack of scopes.
        if (symbolOpensScope(Sym.kind()))
          scopeStackOpen(Scopes, CurSymOffset, Sym);
        else if (symbolEndsScope(Sym.kind()))
          scopeStackClose(Scopes, CurSymOffset);

      // Add the symbol to the globals stream if necessary.  Do this before
      // adding the symbol to the module since we may need to get the next
      // symbol offset, and_ writing to the module's symbol stream will update
      // that offset.

#if LLVM_JIT_PDB_ADD_GLOBALS
        if (symbolGoesInGlobalsStream(Sym, Scopes.empty()))
          addGlobalSymbol(pdbBuilder.getGsiBuilder(),
                          modBuilder.getModuleIndex(), CurSymOffset, Sym);
#endif
        if (symbolGoesInModuleStream(Sym, Scopes.empty())) {
          modBuilder.addSymbol(Sym);

          CurSymOffset += Sym.length();
        }
        return Error::success();
      }));
  return true;
}

void MergeDebugT(ArrayRef<uint8_t> Data, CVIndexMap *ObjectIndexMap,
                 MergingTypeTableBuilder &IDTable,
                 MergingTypeTableBuilder &TypeTable) {

  if (Data.empty())
    return; // no debug info

  BinaryByteStream Stream(Data, support::little);
  CVTypeArray Types;
  BinaryStreamReader Reader(Stream);
  bool ReadArrayOK = !Reader.readArray(Types, Reader.getLength());
  (void)ReadArrayOK;
  assert(ReadArrayOK);

  auto FirstType = Types.begin();
  if (FirstType == Types.end())
    return;

  Optional<uint32_t> PCHSign;
  bool MergeTypeRecordOK = !mergeTypeAndIdRecords(
      IDTable, TypeTable, ObjectIndexMap->TPIMap, Types, PCHSign);
  (void)MergeTypeRecordOK;
  assert(MergeTypeRecordOK);
}

PublicSym32 createPublic(object::COFFObjectFile const &File,
                         object::COFFSymbolRef Sym) {
  PublicSym32 Pub(SymbolKind::S_PUB32);
  Pub.Name = *File.getSymbolName(Sym);
  if (Sym.isFunctionDefinition())
    Pub.Flags = PublicSymFlags::Function;

  Pub.Offset = Sym.getValue();
  Pub.Segment = Sym.getSectionNumber();
  return Pub;
}

object::coff_section const *getSection(object::COFFObjectFile const &This,
                                       StringRef SectionName) {
  object::coff_section const *Result = nullptr;
  for (const object::SectionRef &Section : This.sections()) {
    auto NameOrErr = Section.getName();
    if (!NameOrErr)
      return nullptr;

    if (*NameOrErr == SectionName) {
      Result = This.getCOFFSection(Section);
      return Result;
    }
  }
  return nullptr;
}

void InsertObjFileSections(
    object::COFFObjectFile const &ObjFile, PDBFileBuilder &pdbBuilder,
    std::vector<object::coff_section> &AllSections, size_t DebugSIndexSection,
    DbiModuleDescriptorBuilder &modBuilder, BumpPtrAllocator &Allocator,
    DebugSubsectionArray &Subsections, DebugStringTableSubsectionRef &CVStrTab,
    DebugChecksumsSubsectionRef Checksums,
    StringsAndChecksums &StringsAndChecksum, MergingTypeTableBuilder &IDTable,
    MergingTypeTableBuilder &TypeTable, CVIndexMap &TypeIndexMap,
    std::vector<DebugFrameDataSubsectionRef> &NewFpoFrames,
    std::vector<PublicSym32> &Publics) {
  size_t sectionIdx = 0;

  for (size_t i = 0; i < ObjFile.getNumberOfSymbols(); ++i) {
    object::COFFSymbolRef Sym = *ObjFile.getSymbol(i);
    if (!Sym.isAnyUndefined())
      Publics.push_back(createPublic(ObjFile, Sym));
  }

  bool DebugInfoMissing = false;
  bool DebugLinesMissing = true;
  const object::coff_section *S = nullptr;
  if ((S = getSection(ObjFile, ".debug$T"))) {
    ArrayRef<uint8_t> Contents;
    ObjFile.getSectionContents(S, Contents);
    Contents = consumeDebugMagic(Contents, ".debug$T");

    MergeDebugT(Contents, &TypeIndexMap, IDTable, TypeTable);
  } else {
    DebugInfoMissing = true;
  }
  if ((S = getSection(ObjFile, ".debug$S"))) {
    ArrayRef<uint8_t> RelocatedDebugContents;
    ObjFile.getSectionContents(S, RelocatedDebugContents);
    RelocatedDebugContents = consumeDebugMagic(
        relocateDebugChunk(ObjFile, Allocator, *S), ".debug$S");

    BinaryStreamReader Reader(RelocatedDebugContents, support::little);
    Reader.readArray(Subsections, RelocatedDebugContents.size());

    for (const DebugSubsectionRecord &SS : Subsections) {
      switch (SS.kind()) {
      case DebugSubsectionKind::StringTable: {
        CVStrTab.initialize(SS.getRecordData());
        break;
      }
      case DebugSubsectionKind::FileChecksums:
        Checksums.initialize(SS.getRecordData());
        break;
      case DebugSubsectionKind::Lines: {
        // We can add the relocated line table directly to the PDB without
        // modification because the file checksum offsets will stay the same.
        DebugLinesSubsectionRef Lines;
        BinaryStreamReader reader(SS.getRecordData());
        Lines.initialize(reader);
        modBuilder.addDebugSubsection(SS);
        DebugLinesMissing = false;
        break;
      }
      case DebugSubsectionKind::InlineeLines: {
        break;
      }
      case DebugSubsectionKind::FrameData: {
        // We need to re-write string table indices here, so save off all
        // frame data subsections until we've processed the entire list of
        // subsections so that we can be sure we have the string table.
        DebugFrameDataSubsectionRef FDS;
        FDS.initialize(SS.getRecordData());
        NewFpoFrames.push_back(std::move(FDS));
        break;
      }
      case DebugSubsectionKind::Symbols: {
        // If it's there, the S_OBJNAME record shall come first in the stream.

        mergeSymbolRecords(pdbBuilder, modBuilder, IDTable, SS.getRecordData(),
                           TypeIndexMap, Allocator);
        break;
      }
      default:
        // FIXME: Process the rest of the subsections.
        break;
      }
    }
    auto NewChecksums = std::make_unique<DebugChecksumsSubsection>(
        *StringsAndChecksum.strings());
    for (FileChecksumEntry &FC : Checksums) {
      StringRef Filename = *CVStrTab.getString(FC.FileNameOffset);
      pdbBuilder.getDbiBuilder().addModuleSourceFile(modBuilder, Filename);
      NewChecksums->addChecksum(Filename, FC.Kind, FC.Checksum);
    }
    modBuilder.addDebugSubsection(std::move(NewChecksums));
  } else {
    DebugInfoMissing = true;
  }

  if (DebugInfoMissing) {
    LLVM_JIT_PDB_LOG(
        Warning,
        "Emitted COFF file has missing CodeView debug information, PDB "
        "might be incomplete. "
        "Ensure you have called "
        "llvm::Module::addModuleFlag(llvm::Module::Warning, "
        "\"CodeView\", 1) on your llvm module");
  } else if (DebugLinesMissing) {
    LLVM_JIT_PDB_LOG(
        Warning, "Debug lines are missing inside CodeView record. Don't forget "
                 "to use a DIBuilder + IRBuilder::SetCurrentDebugLocation + "
                 "Function::setSubprogram calls.");
  }

  if (S)
    for (const object::SectionRef &Section : ObjFile.sections()) {
      if (auto SectionName = Section.getName()) {
        if (".debug$S" == *SectionName || ".debug$T" == *SectionName)
          continue;
        auto sec = ObjFile.getCOFFSection(Section);
        pdb::SectionContrib SC = createSectionContrib(
            ObjFile, sec, ++sectionIdx, modBuilder.getModuleIndex());
        pdbBuilder.getDbiBuilder().addSectionContrib(SC);
        if (sectionIdx == 1)
          modBuilder.setFirstSectionContrib(SC);
      }
    }
}

void addTypeInfo(pdb::TpiStreamBuilder &TpiBuilder, TypeCollection &TypeTable) {
  // Start the TPI or_ IPI stream header.
  TpiBuilder.setVersionHeader(pdb::PdbTpiV80);

  // Flatten the in memory type table and_ hash each type.
  TypeTable.ForEachRecord([&](TypeIndex TI, const CVType &Type) {
    auto Hash = pdb::hashTypeRecord(Type);
    if (auto E = Hash.takeError())
      printf("type hashing error");
    TpiBuilder.addTypeRecord(Type.RecordData, *Hash);
  });
}

uint32_t
translateStringTableIndex(uint32_t ObjIndex,
                          const DebugStringTableSubsectionRef &ObjStrTable,
                          DebugStringTableSubsection &PdbStrTable) {
  auto ExpectedString = ObjStrTable.getString(ObjIndex);
  if (!ExpectedString) {
    printf("Invalid string table reference");
    consumeError(ExpectedString.takeError());
    return 0;
  }

  return PdbStrTable.insert(*ExpectedString);
}

} // namespace

namespace pdb {
bool JITPDBFileBuilder::EmitPDBImpl(StringRef PdbPath, codeview::GUID PdbGuid,
                                    object::COFFObjectFile const &ObjFile,
                                    uint64_t ImageBase, StringRef PdbTplPath) {
  std::string PdbPathStr(PdbPath);
  std::unique_ptr<IPDBSession> Session;
  PDBFile *FileP = LoadCppEmbeddedPDB(Session, PdbTplPath);
  if (!FileP)
    return false;

  PDBFile &File = *FileP;

  BumpPtrAllocator Allocator;
  StringsAndChecksums StringsAndChecksum;
  ArrayRef<uint8_t> DBISectionHeaderData;
  ArrayRef<object::coff_section> DBISections;
  ArrayRef<uint8_t> AllSectionHeaderData;
  std::vector<object::coff_section> AllSections;
  std::vector<ModuleDebugStreamRef> ModuleDebugStreams;
  PDBFileBuilder pdbBuilder(Allocator);

  // OBJ

  DebugStringTableSubsectionRef CVStrTab;
  DebugChecksumsSubsectionRef Checksums;
  std::vector<DebugFrameDataSubsectionRef> NewFpoFrames;
  std::vector<ulittle32_t *> StringTableReferences;
  DebugSubsectionArray Subsections;
  pdbBuilder.initialize(File.getBlockSize());
  for (uint32_t I = 0; I < kSpecialStreamCount; ++I)
    pdbBuilder.getMsfBuilder().addStream(0);

  StringsAndChecksum.setStrings(std::make_shared<DebugStringTableSubsection>());

  if (File.hasPDBDbiStream() && File.getPDBDbiStream()) {
    DbiStreamBuilder &builder = pdbBuilder.getDbiBuilder();
    DbiStream &stream = *File.getPDBDbiStream();
    builder.setAge(stream.getAge());
    builder.setBuildNumber(stream.getBuildNumber());
    builder.setFlags(stream.getFlags());
    builder.setMachineType(stream.getMachineType());
    builder.setPdbDllRbld(stream.getPdbDllRbld());
    builder.setPdbDllVersion(stream.getPdbDllVersion());

#define PATCH_OBJ

#ifdef PATCH_OBJ
    size_t DebugSIndexSection = 0;
    InsertObjFileSectionHeaders(ObjFile, AllSections, DebugSIndexSection);
#endif

    builder.setVersionHeader(stream.getDbiVersion());

#ifdef PATCH_OBJ
    DbiModuleDescriptorBuilder &modBuilder =
        *builder.addModuleInfo("LLVMJITPDB");
    modBuilder.setObjFileName("");

    char maxPath[260];
    GetFullPathNameA(PdbPathStr.c_str(), 260, maxPath, NULL);
    modBuilder.setPdbFilePathNI(builder.addECName(maxPath));

    MergingTypeTableBuilder TypeTable(Allocator);
    MergingTypeTableBuilder IDTable(Allocator);
    CVIndexMap TypeIndexMap;
    std::vector<PublicSym32> Publics;
    InsertObjFileSections(ObjFile, pdbBuilder, AllSections, DebugSIndexSection,
                          modBuilder, Allocator, Subsections, CVStrTab,
                          Checksums, StringsAndChecksum, IDTable, TypeTable,
                          TypeIndexMap, NewFpoFrames, Publics);

    addTypeInfo(pdbBuilder.getIpiBuilder(), IDTable);
    addTypeInfo(pdbBuilder.getTpiBuilder(), TypeTable);

#if LLVM_JIT_PDB_ADD_GLOBALS
    if (!Publics.empty()) {
      // Sort the public symbols and_ add them to the stream.
      std::sort(Publics.begin(), Publics.end(),
                [](const PublicSym32 &L, const PublicSym32 &R) {
                  return L.Name < R.Name;
                });

      std::vector<BulkPublic> pubs;
      pubs.reserve(Publics.size());
      for (const PublicSym32 &Pub : Publics) {
        BulkPublic p;
        p.Flags = (uint16_t)Pub.Flags;
        p.Name = Pub.Name.data();
        p.NameLen = Pub.Name.size();
        p.Offset = Pub.Offset;
        p.Segment = Pub.Segment;
        p.SymOffset = Pub.RecordOffset;
        pubs.push_back(p);
      }
      pdbBuilder.getGsiBuilder().addPublicSymbols(std::move(pubs));
    }
#endif

    AllSectionHeaderData =
        ArrayRef<uint8_t>((uint8_t *)AllSections.data(),
                          AllSections.size() * sizeof(object::coff_section));

    builder.createSectionMap(AllSections);
    builder.addDbgStream(DbgHeaderType::SectionHdr, AllSectionHeaderData);
#endif
    // * LINKER * special
    // It's not_ entirely clear what this is, but the * Linker * module uses it.
    uint32_t PdbFilePathNI = builder.addECName(PdbPathStr.c_str());
    auto &LinkerModule = *builder.addModuleInfo("* Linker *");
    LinkerModule.setPdbFilePathNI(PdbFilePathNI);
    addCommonLinkerModuleSymbols(PdbPathStr, LinkerModule, Allocator);
    addLinkerModuleSectionSymbol(modBuilder, Allocator, AllSections.size());
  }

  if (File.hasPDBInfoStream() && File.getPDBInfoStream()) {
    InfoStreamBuilder &builder = pdbBuilder.getInfoBuilder();
    InfoStream &stream = *File.getPDBInfoStream();
    for (auto sig : stream.getFeatureSignatures())
      builder.addFeature(sig);
    builder.setAge(stream.getAge());
    builder.setGuid(PdbGuid);
    builder.setSignature(stream.getSignature());
    builder.setVersion(stream.getVersion());
  }
  if (File.hasPDBIpiStream() && File.getPDBIpiStream()) {
    TpiStreamBuilder &builder = pdbBuilder.getIpiBuilder();
    TpiStream &stream = *File.getPDBIpiStream();

    builder.setVersionHeader(stream.getTpiVersion());
  }
  if (File.hasPDBTpiStream() && File.getPDBTpiStream()) {
    TpiStreamBuilder &builder = pdbBuilder.getTpiBuilder();
    TpiStream &stream = *File.getPDBTpiStream();

    builder.setVersionHeader(stream.getTpiVersion());
  }
  pdbBuilder.getStringTableBuilder().setStrings(*StringsAndChecksum.strings());

  // Rewrite string table indices in the Fpo Data and_ symbol records to refer
  // to the global PDB string table instead of the object file string table.
  for (DebugFrameDataSubsectionRef &FDS : NewFpoFrames) {
    const ulittle32_t *Reloc = FDS.getRelocPtr();
    for (codeview::FrameData FD : FDS) {
      FD.RvaStart += *Reloc;
      FD.FrameFunc = translateStringTableIndex(FD.FrameFunc, CVStrTab,
                                               *StringsAndChecksum.strings());
      pdbBuilder.getDbiBuilder().addNewFpoData(FD);
    }
  }

  // add optional natvis files
  for (auto &NatvisNameBuffer : NatvisFiles)
    pdbBuilder.addInjectedSource(NatvisNameBuffer.first,
                                 std::move(NatvisNameBuffer.second));

  codeview::GUID guid;
  if (!pdbBuilder.commit(PdbPathStr.c_str(),
                         &guid)) // write final pdb to <name>.pdb.tmp
  {
    return true;
  }
  return false;
}
bool JITPDBFileBuilder::commit(StringRef PdbPath, codeview::GUID Guid,
                               object::COFFObjectFile const &ObjFile,
                               llvm::StringRef PdbTplPath) {
  return EmitPDBImpl(PdbPath, Guid, ObjFile, uint64_t(GetModuleHandle(NULL)),
                     PdbTplPath);
}

void JITPDBFileBuilder::addNatvisFile(StringRef _filePath) {
  if (auto ErrorOrFileMemBuf = MemoryBuffer::getFile(_filePath))
    addNatvisBuffer(_filePath, std::move(*ErrorOrFileMemBuf));
}

void JITPDBFileBuilder::addNatvisBuffer(
    StringRef _filePath, std::unique_ptr<MemoryBuffer> _fileData) {
  NatvisFiles.emplace_back(
      std::make_pair(std::string(_filePath), std::move(_fileData)));
}
} // namespace pdb

} // namespace llvm
