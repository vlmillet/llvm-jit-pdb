# LLVM Jit Pdb
Debugging LLVM JIT code inside Visual Studio with PDB

# Getting started 
I assume you already know what is a MemoryManager in llvm jit system. If not, follow the Kaleidoscope JIT Tutorial on LLVM.

Just create a ```JITPDBMemoryManager``` and use it either in your MCJIT or OrcJit setup. (I've only tried MCJIT right now, please let me know if something doesn't work with OrcJIT, the project is quite young).

```
auto MemMgr = std::make_unique<JITPDBMemoryManager>("MyModule.pdb", [](void* EmittedDllBaseAddress) 
  { 
    printf("MyModule.dll has been loaded at 0x%p and is now debuggable", EmittedDllBaseAddress); 
  } 
);

```
And then call JITPDBMemoryManager::finalize() to load the backing .dll (see below) and make the code ready for you and visual studio to debug.

```
MemMgr->finalize(); // this will ensure a .dll is emitted and pdb loaded inside current visual studio debugger
```

# How it works

LLVM Jit Pdb works like this :
- a dummy .dll is written from C++ byte array embedded data to the disk (beside the .pdb user path) and loaded.
- Jitted code is allocated directly inside dll image (write access have been allowed)
- PDB is generated based on the COFFObjectFile emitted by the llvm RuntimeDyld engine.
- Dll is unloaded with a memory backup on ram.
- Dll is written/hacked on disk for various stuff (pdb matching, guid, timestamp, code sections, unwind infos, access rights).
- Dll is reloaded with everything coming back at the same VirtualSpace it has been written (by chance).
- This triggers PDB loading inside visual studio and a great C++/Script interleaved debug experience. 

The embedded .dll and .pdb data have limitation in size for now as I'm not an expert in creating .dll from scratch. The limitation is around 5MB for code and 5MB for data. It might seem little, but I personnally only reach 4% of code and 1% data on my personal project.
You can enabled the Verbose property on the memory manager to follow your memory consumption.
I've chosen this for a start and because it is quite light for distribution.
I'm planning to learn more about .dll generation from zero and propose more size configuration options in the future. 

Any help is welcome for the .dll generation part !

# Donation

You can help me support this project and my other project https://github.com/vlmillet/phantom on my baby patreon :)) 
https://www.patreon.com/vlmillet
