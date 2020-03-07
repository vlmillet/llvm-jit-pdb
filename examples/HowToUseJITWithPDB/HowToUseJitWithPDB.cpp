//===-- examples/HowToUseJITWithPDB/HowToUseJITWithPDB.cpp - An example use of
// the JIT and debugging it with a PDB --===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This small program provides an example of how to quickly build a small
//  module with two functions, add debug informations, execute it with the JIT
//  and debug it inside visual studio with PDB.
//
// Goal:
//  The goal of this snippet is to create in the memory
//  the LLVM module consisting of two functions as follow:
//
// int add1(int x) {
//   return x+1;        // place a breakpoint here
// }
//
// int foo() {
//   return add1(10);   // or here
// }
//
// then compile the module via JIT, then execute the `foo'
// function and return result to a driver, i.e. to a "host program".
// You can insert breakpoints inside this code sample above to step into the JIT
// code and watch variable/callstack in Visual Studio or any other PDB debugger.
//
// Some remarks and questions:
//
// - could we invoke some code using noname functions too?
//   e.g. evaluate "foo()+foo()" without fears to introduce
//   conflict of temporary function name with some real
//   existing function name?
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/STLExtras.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/JITPDB/JITPDBMemoryManager.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cassert>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <memory>
#include <vector>

using namespace llvm;

int main() {
  InitializeNativeTarget();
  InitializeNativeTargetAsmPrinter();
  InitializeNativeTargetDisassembler();

  LLVMContext Context;

  // Create some module to put our function into it.
  std::unique_ptr<Module> Owner =
      make_unique<Module>("HowToUseJITWithPDB", Context);
  Module *M = Owner.get();

  // ensure CodeView debug info is emitted instead of default Dwarf
  M->addModuleFlag(Module::Warning, "CodeView", 1);

  // ----- DEBUG INFO -----

  int lineBase = 19; // of this file (code inside comment will be debuggable :))

  // Create a debug info builder for this module with default parameters.
  DIBuilder dibuilder(*M);

  // Create a debug info file with computed MD5 for PDB.
  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> MemBuf =
      llvm::MemoryBuffer::getFileAsStream(__FILE__);
  assert(MemBuf);

  llvm::MD5 Hash;
  llvm::MD5::MD5Result Result;

  Hash.update((*MemBuf)->getBuffer());
  Hash.final(Result);

  llvm::SmallString<32> Checksum;

  Hash.stringifyResult(Result, Checksum);

  llvm::DIFile::ChecksumInfo<llvm::StringRef> ChecksumInfo(
      llvm::DIFile::CSK_MD5, Checksum);
  SmallString<260> path;
  llvm::sys::fs::real_path(__FILE__, path);
  for (auto &c : path)
    if (c == '\\')
      c = '/';
  DIFile *file = dibuilder.createFile(path, "", ChecksumInfo);

  // Create a debug info compilation unit with C as the language identifier.
  DICompileUnit *cunit = dibuilder.createCompileUnit(llvm::dwarf::DW_LANG_C,
                                                     file, "", false, "", 0);

  // Create the C 'int' type debug info
  DIType *diIntType =
      dibuilder.createBasicType("int", 32, dwarf::DW_ATE_signed);

  // -------- IR ---------

  // Create the add1 function entry and insert this entry into module M.  The
  // function will have a return type of "int" and take an argument of "int".
  Function *Add1F = cast<Function>(M->getOrInsertFunction(
      "add1", Type::getInt32Ty(Context), Type::getInt32Ty(Context)));

  // add some function attributes to ensure good debug experience
  Add1F->addAttribute(AttributeList::FunctionIndex, Attribute::OptimizeNone);
  Add1F->addAttribute(AttributeList::FunctionIndex, Attribute::NoInline);
  Add1F->addAttribute(AttributeList::FunctionIndex, Attribute::UWTable);

  // Add a basic block to the function. As before, it automatically inserts
  // because of the last argument.
  BasicBlock *BB = BasicBlock::Create(Context, "EntryBlock", Add1F);

  // Create a basic block builder with default parameters.  The builder will
  // automatically append instructions to the basic block `BB'.
  IRBuilder<> builder(BB);

  // ----- DEBUG INFO -----

  SmallVector<Metadata *, 2> add1Params{diIntType,
                                        diIntType}; // return type + param type

  DISubroutineType *add1FuncType = dibuilder.createSubroutineType(
      dibuilder.getOrCreateTypeArray(makeArrayRef(add1Params)),
      DINode::FlagZero, llvm::dwarf::DW_CC_LLVM_Win64);

  // create debug info for add1 function
  DISubprogram *diAdd1F = dibuilder.createFunction(
      cunit, "add1", "add1", file, lineBase, add1FuncType, lineBase,
      llvm::DINode::FlagZero, llvm::DISubprogram::SPFlagDefinition);
  Add1F->setSubprogram(diAdd1F);
  // -------- IR ---------

  // Get pointers to the constant `1'.
  Value *One = builder.getInt32(1);

  // Get pointers to the integer argument of the add1 function...
  assert(Add1F->arg_begin() != Add1F->arg_end()); // Make sure there's an arg
  Argument *ArgX = &*Add1F->arg_begin();          // Get the arg
  ArgX->setName("AnArg"); // Give it a nice symbolic name for fun.

  // for debugging purpose it is recommended to store the argument value on
  // stack
  Value *localArg = builder.CreateAlloca(builder.getInt32Ty());
  builder.CreateStore(ArgX, localArg);

  // ----- DEBUG INFO -----

  // this will give hint to debug info on how to retrieve the argument on the
  // stack
  dibuilder.insertDeclare(localArg,
                          dibuilder.createParameterVariable(
                              diAdd1F, "x", 1, file, lineBase, diIntType, true),
                          dibuilder.createExpression(),
                          DebugLoc::get(lineBase, 1, diAdd1F),
                          &Add1F->getEntryBlock());

  // -------- IR ---------

  // debug line
  builder.SetCurrentDebugLocation(
      llvm::DebugLoc::get(lineBase + 1, 1, diAdd1F));

  // Create the add instruction, inserting it into the end of BB.
  Value *Add = builder.CreateAdd(One, builder.CreateLoad(localArg));

  // debug line
  builder.SetCurrentDebugLocation(
      llvm::DebugLoc::get(lineBase + 2, 1, diAdd1F));

  // Create the return instruction and add it to the basic block
  builder.CreateRet(Add);

  // Now, function add1 is ready.

  // Now we're going to create function `foo', which returns an int and takes no
  // arguments.
  Function *FooF =
      cast<Function>(M->getOrInsertFunction("foo", Type::getInt32Ty(Context)));

  // add some function attributes to ensure good debug experience
  FooF->addAttribute(AttributeList::FunctionIndex, Attribute::OptimizeNone);
  FooF->addAttribute(AttributeList::FunctionIndex, Attribute::NoInline);
  FooF->addAttribute(AttributeList::FunctionIndex, Attribute::UWTable);

  // Add a basic block to the FooF function.
  BB = BasicBlock::Create(Context, "EntryBlock", FooF);

  // Tell the basic block builder to attach itself to the new basic block
  builder.SetInsertPoint(BB);

  // ----- DEBUG INFO -----

  SmallVector<Metadata *, 2> fooParams{diIntType}; // return type

  DISubroutineType *fooFuncType = dibuilder.createSubroutineType(
      dibuilder.getOrCreateTypeArray(makeArrayRef(fooParams)), DINode::FlagZero,
      llvm::dwarf::DW_CC_LLVM_Win64);

  DISubprogram *diFooF = dibuilder.createFunction(
      cunit, "foo", "foo", file, lineBase + 4, fooFuncType, lineBase + 4,
      llvm::DINode::FlagZero, llvm::DISubprogram::SPFlagDefinition);
  FooF->setSubprogram(diFooF);

  // -------- IR ---------

  // Get pointer to the constant `10'.
  Value *Ten = builder.getInt32(10);

  // debug line
  builder.SetCurrentDebugLocation(llvm::DebugLoc::get(lineBase + 5, 1, diFooF));

  // Pass Ten to the call to Add1F
  CallInst *Add1CallRes = builder.CreateCall(Add1F, Ten);
  Add1CallRes->setTailCall(true);

  // Create the return instruction and add it to the basic block.
  builder.CreateRet(Add1CallRes);

  dibuilder.finalize();

  // Now we create the JIT with debug info emitted in a PDB.
  ExecutionEngine *EE =
      EngineBuilder(std::move(Owner))
          .setMemoryManager(
              std::make_unique<JITPDBMemoryManager>("HowToUseAJitWithPDB.pdb"))
          .create();

  auto pTarget = EE->getTargetMachine();
  M->setTargetTriple(pTarget->getTargetTriple().str());

  outs() << "We just constructed this LLVM module:\n\n" << *M;
  outs() << "\n\nRunning foo: ";
  outs() << "\n\n(Don't forget to put your breakpoints inside the commented "
            "code in description)"
         << *M;
  outs().flush();
  // Call the `foo' function with no arguments:
  std::vector<GenericValue> noargs;
  GenericValue gv = EE->runFunction(FooF, noargs);

  // Import result of execution:
  outs() << "Result: " << gv.IntVal << "\n";
  delete EE;
  llvm_shutdown();
  return 0;
}
