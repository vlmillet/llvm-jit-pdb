set(LLVM_LINK_COMPONENTS
  Core
  ExecutionEngine
  Interpreter
  Support
  nativecodegen
  JITPDB
  MCJIT
  X86Disassembler
  X86AsmPrinter
  )

add_llvm_example(HowToUseJITWithPDB
  HowToUseJITWithPDB.cpp
  )
