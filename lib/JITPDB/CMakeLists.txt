add_llvm_library(LLVMJITPDB
  JITPDBMemoryManager.cpp
  JITPDBFileBuilder.cpp
  JITPDBEmbeddedData.cpp

  ADDITIONAL_HEADER_DIRS
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/JITPDB

  )
