#include "instrument.h"

#include <cstdio>
#include <vector>
#include <algorithm>

// #define INST_TRACE_ENABLE 1

#define INJECT_FUNC_CALL_WITH_HVAL(i_call, hval, func_name, module, ctxt) \
  IRBuilder<> builder(i_call); \
  FunctionType *funcTy = FunctionType::get( \
    Type::getVoidTy(ctxt), \
    { \
      Type::getInt64Ty(ctxt) \
    }, \
    /*IsVarArgs=*/false); \
  builder.CreateCall( \
    module.getOrInsertFunction(func_name, funcTy), \
    {ConstantInt::get(Type::getInt64Ty(ctxt), hval)}); \


namespace PMRace {
  void Instrumentor::run() {
    prepare();

    // populate hook points for every block
    for (auto &i : blockHT) {
      getBlockHookPoint(i.first);
    }

    // main
    inst_main();

    // Branch coverage
    inst_branch_enter();

    // iterate instructions
    iter_inst();

    // PMEM region
    if (mode == "pmdk") {
      inst_pmdk_pmem_region();
    } else {
      inst_raw_pmem_region();
    }

    // external calls
    handle_external_call();

    dump();
  }

  void Instrumentor::prepare() {
    // prepare constants
    uint64_t blockCount = 0;
    uint64_t instCount = 0;

    for (Function &f : module) {
      // ignore functions without body
      if (f.isIntrinsic() || f.isDeclaration()) {
          continue;
      }

      // errs() << "Func " << f.getName() << "\n";
      // calculate the function hash
      hash_code funcHash = hash_combine(
        seed, hash_value(f.getName().str())
      );
      funcHT.emplace(&f, funcHash);

      // per-block enumerate
      for (BasicBlock &bb : f) {
        hash_code blockHash = hash_combine(funcHash, blockCount++);
        blockHT.emplace(&bb, blockHash);

        // per-instruction enumerate
        for (Instruction &i : bb) {
          hash_code instHash = hash_combine(blockHash, instCount++);
          instHT.emplace(&i, instHash);
        }
      }
    }

  }

  void Instrumentor::inst_main() {
    for (auto &f : funcHT) {
      Function *func = f.first;

      if (func->getName().str() == "main") {

        // main start
        {
          Instruction *instInit = getFunctionEntryPoint(func);
          IRBuilder<> builder(instInit);

          // We expect the hook prototype to be:
            //   void hook_main_enter()
          FunctionType *funcTy = FunctionType::get(
            Type::getVoidTy(ctxt),
            {},
            /*IsVarArgs=*/false);
          builder.CreateCall(
            module.getOrInsertFunction("hook_main_enter", funcTy), {});
        }

        // main return
        {
          std::vector<Instruction *> exits = getFunctionExitPoints(func);
          for (Instruction *instFini : exits) {
            IRBuilder<> builder(instFini);

            // We expect the hook prototype to be:
            //   void hook_main_exit()
            FunctionType *funcTy = FunctionType::get(
              Type::getVoidTy(ctxt),
              {},
              /*IsVarArgs=*/false);
            builder.CreateCall(
              module.getOrInsertFunction("hook_main_exit", funcTy), {});
          }
        }
      }
    }
  }

  void Instrumentor::inst_branch_enter() {
    // branch coverage
    for (auto &i : blockHT) {
      IRBuilder<> builder(getBlockHookPoint(i.first));

      FunctionType *funcTy = FunctionType::get(
        Type::getVoidTy(ctxt),
        {Type::getInt64Ty(ctxt)},
        /*IsVarArgs=*/false);
      builder.CreateCall(
        module.getOrInsertFunction("hook_branch_enter", funcTy),
        {ConstantInt::get(Type::getInt64Ty(ctxt), i.second)});
    }
  }

  void Instrumentor::inst_mem_access(
    bool isStore, IRBuilder<> &builder, Instruction *inst,
    Value *flags, Value *hval, Value *addr, Value *size
  ) {
    // IRBuilder<> builder(inst);
    FunctionType *funcTy = FunctionType::get(
      Type::getVoidTy(ctxt),
      {
        Type::getInt32Ty(ctxt),
        Type::getInt64Ty(ctxt),
        Type::getInt64Ty(ctxt),
        Type::getInt64Ty(ctxt),
#ifdef INST_TRACE_ENABLE
        PointerType::getUnqual(Type::getInt8Ty(ctxt)),
        PointerType::getUnqual(Type::getInt8Ty(ctxt))
#endif
      },
      /*IsVarArgs=*/false);
    FunctionCallee func = module.getOrInsertFunction(
      isStore ? "hook_mem_write" : "hook_mem_read",
      funcTy
    );

#ifdef INST_TRACE_ENABLE
    Value *msg1 = builder.CreateGlobalStringPtr(
      printRepr(inst).c_str());
    const DebugLoc &loc = inst->getDebugLoc();
    Value *msg2 = builder.CreateGlobalStringPtr(
      printDebugRepr(&inst->getDebugLoc()).c_str());
#endif

    builder.CreateCall(
      func,
      {
        flags,
        hval,
        addr,
        size,
#ifdef INST_TRACE_ENABLE
        msg1,
        msg2
#endif
    });
  }

  void Instrumentor::iter_inst() {
    const DataLayout layout = module.getDataLayout();

       for (auto &i : instHT) {
         Instruction *inst = i.first;

        // load instructions
        if (auto *i_load = dyn_cast<LoadInst>(inst)) {
          uint64_t size = layout.getTypeStoreSizeInBits(i_load->getType()) / 8;

          IRBuilder<> builder(i_load);
          inst_mem_access(
            /*isStore=*/false, builder, i_load,
            builder.getInt32(0),
            ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
            builder.CreatePtrToInt(i_load->getPointerOperand(), Type::getInt64Ty(ctxt)),
            builder.getInt64(size)
          );

          continue;
        }

        // store instructions
        if (auto *i_store = dyn_cast<StoreInst>(inst)) {
          bool isNonTemporal = i_store->getMetadata(LLVMContext::MD_nontemporal) != nullptr;
          // if (isNonTemporal) {
          //   errs() << "Non-temporal store: \n\t";
          //   i_store->print(errs());
          //   errs() << "\n";
          // }
          // IRBuilder<> builder(i_store);

          uint64_t size = layout.getTypeStoreSizeInBits(
            i_store->getValueOperand()->getType()) / 8;

          // insert after store
          IRBuilder<> builder(i_store->getNextNode());
          inst_mem_access(
            /*isStore=*/true, builder, i_store,
            builder.getInt32(isNonTemporal),
            ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
            builder.CreatePtrToInt(i_store->getPointerOperand(), Type::getInt64Ty(ctxt)),
            builder.getInt64(size)
          );

          continue;
        }

        // "atomicrmw" instructions or "cmpxchg" instruction
        {
        auto *i1 = dyn_cast<AtomicRMWInst>(inst);
        auto *i2 = dyn_cast<AtomicCmpXchgInst>(inst);
        if (i1 || i2) {
          Instruction *i_atomic;
          Value *addr;
          uint64_t size;
          if (i1) {
            i_atomic = i1;
            addr = i1->getPointerOperand();
            size = layout.getTypeStoreSizeInBits(i1->getValOperand()->getType()) / 8;
            // errs() << "atomicRMW (read + write) hval ( " << i.second << " )!\n";
            // i_atomic->print(errs());
            // errs() << "\n";
          } else {
            i_atomic = i2;
            addr = i2->getPointerOperand();
            size = layout.getTypeStoreSizeInBits(i2->getNewValOperand()->getType()) / 8;
            // errs() << "cmpxchg (read + write) hval ( " << i.second << " )!\n";
            // i_atomic->print(errs());
            // errs() << "\n";
          }

          IRBuilder<> builder(i_atomic);
          inst_mem_access(
            /*isStore=*/false, builder, i_atomic,
            builder.getInt32(0),
            ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
            builder.CreatePtrToInt(addr, Type::getInt64Ty(ctxt)),
            builder.getInt64(size)
          );

          // insert after atomic instructions
          IRBuilder<> store_builder(i_atomic->getNextNode());
          inst_mem_access(
            /*isStore=*/true, store_builder, i_atomic,
            store_builder.getInt32(0),
            ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
            store_builder.CreatePtrToInt(addr, Type::getInt64Ty(ctxt)),
            store_builder.getInt64(size)
          );

          continue;
        }
        }

        // persistency states
        if (auto *i_call = dyn_cast<CallInst>(inst)) {
          Function *func = i_call->getCalledFunction();
          if (func == nullptr) {
            // errs() << "[iter_inst] Skip indirect call: " << i_call << "\n";
            continue;
          }

          // cache flushed
          if (func->getIntrinsicID() == Intrinsic::x86_sse2_clflush
            || func->getIntrinsicID() == Intrinsic::x86_clflushopt
            || func->getIntrinsicID() == Intrinsic::x86_clwb) {
            // errs() << "Found persistency Call: " << func->getName() << "\n";

            IRBuilder<> builder(i_call);

            // We expect the hook prototype to be:
            //    void hook_cache_flush(uint64_t addr, hval_64_t hval)
            FunctionType *funcTy = FunctionType::get(
              Type::getVoidTy(ctxt),
              {
                Type::getInt64Ty(ctxt),
                Type::getInt64Ty(ctxt)
              },
              /*IsVarArgs=*/false);

            // errs() << func->getName() << "(" << i_call->getArgOperand(0) << ")\n";
            builder.CreateCall(
              module.getOrInsertFunction("hook_cache_flush", funcTy),
              {
                builder.CreatePtrToInt(i_call->getArgOperand(0), Type::getInt64Ty(ctxt)),
                ConstantInt::get(Type::getInt64Ty(ctxt), i.second)
              });

            continue;
          }

          // pmemobj_tx_begin (TX_BEGIN)
          if (func->getName().equals("pmemobj_tx_begin")) {
            // "pmemobj_tx_begin" prototype
            //   int pmemobj_tx_begin(PMEMobjpool *pop, jmp_buf env, ...)
            // errs() << "Found pmemobj_tx_begin call: " << func->getName() << "\n";

            // insert after pmemobj_tx_begin
            IRBuilder<> builder(i_call->getNextNode());

            // We expect the hook prototype to be:
            //    void hook_pmemobj_tx_begin(uint64_t hval, uint64 pool_addr)
            FunctionType *funcTy = FunctionType::get(
              Type::getVoidTy(ctxt),
              {
                Type::getInt64Ty(ctxt),
                Type::getInt64Ty(ctxt)
              },
              /*IsVarArgs=*/false);

            Value *popArg = i_call->getArgOperand(0);

            builder.CreateCall(
              module.getOrInsertFunction("hook_pmemobj_tx_begin", funcTy),
              {
                ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
                builder.CreatePtrToInt(popArg, Type::getInt64Ty(ctxt))
              });

            continue;
          }

          // pmemobj_tx_add_common (TX_ADD)
          if (func->getName().equals("pmemobj_tx_add_common")) {
            // errs() << "Found pmemobj_tx_add_common call: " << func->getName();
            // errs() << ", #args: " << i_call->getNumArgOperands()  << "\n";

            // i_call->print(errs());
            // errs() << "\n" << printDebugRepr(&i_call->getDebugLoc()) << "\n";


            IRBuilder<> builder(i_call->getNextNode());

            // We expect the hook prototype to be:
            //   void hook_pmemobj_tx_add_common(
            //     uint64_t hval,
            //     uint64_t tx_offset_addr,
            //     uint64_t tx_size_addr
            //   )
            FunctionType *funcTy = FunctionType::get(
              Type::getVoidTy(ctxt),
              {
                Type::getInt64Ty(ctxt),
                Type::getInt64Ty(ctxt),
                Type::getInt64Ty(ctxt)
              },
              /*IsVarArgs=*/false);

            // The second arg (pointer) of pmemobj_tx_add_common:
            //   struct tx_range_def {
            //     uint64_t offset;
            //     uint64_t size;
            //     uint64_t flags;
            //   };
            Value *txRangeArg = i_call->getArgOperand(1);
            Value *txOffsetArg = builder.CreateGEP(
              txRangeArg, {builder.getInt32(0), builder.getInt32(0)});
            Value *txSizeArg = builder.CreateGEP(
              txRangeArg, {builder.getInt32(0), builder.getInt32(1)});

            builder.CreateCall(
              module.getOrInsertFunction("hook_pmemobj_tx_add_common", funcTy),
              {
                ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
                builder.CreatePtrToInt(txOffsetArg, Type::getInt64Ty(ctxt)),
                builder.CreatePtrToInt(txSizeArg, Type::getInt64Ty(ctxt))
              });

            continue;
          }

          // pmemobj_tx_end (TX_END)
          if (func->getName().equals("pmemobj_tx_end")) {
            // errs() << "Found pmemobj_tx_end call: " << func->getName() << "\n";

            // We expect the hook prototype to be:
            //    void hook_pmemobj_tx_end(uint64_t hval)
            INJECT_FUNC_CALL_WITH_HVAL(i_call, i.second, "hook_pmemobj_tx_end", module, ctxt)

            continue;
          }

          // hints for synchronization variables:
          //    "llvm.var.annotation" or "llvm.ptr.annotation"
          if (func->getName().equals("llvm.var.annotation") ||
              func->getName().startswith("llvm.ptr.annotation")) {
            ConstantExpr *ce = dyn_cast<ConstantExpr>(i_call->getOperand(1));
            assert(ce && ce->getOpcode() == Instruction::GetElementPtr);

            if (auto *annoteStr = dyn_cast<GlobalVariable>(ce->getOperand(0))) {
              ConstantDataSequential *data = dyn_cast<ConstantDataSequential>(
                annoteStr->getInitializer());
              if (data && data->isString() && data->getAsString().startswith("sync-")) {
                errs() << "Found annotation: " << data->getAsString() << "\n";
                auto size_val_t = data->getAsString().substr(5).split("-");

                IRBuilder<> builder(i_call->getNextNode());

                // The prototype should be:
                //   void hook_annotation(uint64_t hval, uint64_t var_addr, uint64_t size, uint64_t val)
                FunctionType *funcTy = FunctionType::get(
                  Type::getVoidTy(ctxt),
                  {
                    Type::getInt64Ty(ctxt),
                    Type::getInt64Ty(ctxt),
                    Type::getInt64Ty(ctxt),
                    Type::getInt64Ty(ctxt)
                  },
                  /*IsVarArgs=*/false);

                Value *base = i_call->getArgOperand(0);
                Value *size = builder.getInt64(stoi(size_val_t.first.str()));
                Value *init_val = builder.getInt64(stoi(size_val_t.second.str()));

                builder.CreateCall(
                  module.getOrInsertFunction("hook_annotation", funcTy),
                  {
                    ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
                    builder.CreatePtrToInt(base, Type::getInt64Ty(ctxt)),
                    size,
                    init_val
                  });
              }
            }

            continue;
          }

        }
    }
  }

  void Instrumentor::inst_pmdk_pmem_region() {

    for (auto &i : instHT) {
      Instruction *inst = i.first;
      if (auto *i_call = dyn_cast<CallInst>(inst)) {
        Function *func = i_call->getCalledFunction();
        if (func == nullptr) {
          // errs() << "[inst_pmdk_pmem_region] Skip indirect call: " << i_call << "\n";
          continue;
        }

        // obj_runtime_init
        if (func->getName().equals("obj_runtime_init")) {
          // "obj_runtime_init" prototype
          //   int obj_runtime_init(PMEMobjpool *pop, int rdonly, int boot, unsigned nlanes)
          // errs() << "Found obj_runtime_init call: " << func->getName() << "\n";

          // insert after obj_runtime_init
          IRBuilder<> builder(i_call->getNextNode());

          // We expect the hook prototype to be:
          //     void hook_obj_runtime_init(
          //       uint64_t pool_addr,
          //       uint64_t heap_offset_addr,
          //       uint64_t heap_size_addr
          //     )
          FunctionType *funcTy = FunctionType::get(
            Type::getVoidTy(ctxt),
            {
              Type::getInt64Ty(ctxt),
              Type::getInt64Ty(ctxt),
              Type::getInt64Ty(ctxt)
            },
            /*IsVarArgs=*/false);

          Value *popArg = i_call->getArgOperand(0);
          Value *heapOffsetArg = builder.CreateGEP(
            popArg, {builder.getInt32(0), builder.getInt32(4)});
          Value *heapSizeArg = builder.CreateGEP(
            popArg, {builder.getInt32(0), builder.getInt32(12)});

          builder.CreateCall(
            module.getOrInsertFunction("hook_obj_runtime_init", funcTy),
            {
              builder.CreatePtrToInt(popArg, Type::getInt64Ty(ctxt)),
              builder.CreatePtrToInt(heapOffsetArg, Type::getInt64Ty(ctxt)),
              builder.CreatePtrToInt(heapSizeArg, Type::getInt64Ty(ctxt))
            });
        }

        // pmem_map_fileU
        else if (func->getName().equals("pmem_map_fileU")) {
          // "pmem_map_fileU" prototype
          // void *pmem_map_fileU(const char *path, size_t len, int flags,
          //                      mode_t mode, size_t *mapped_lenp, int
          //                      *is_pmemp);
          // errs() << "Found pmem_map_fileU call: " << func->getName() << "\n";

          // insert after pmem_map_fileU
          IRBuilder<> builder(i_call->getNextNode());

          // We expect the hook prototype to be:
          //  void hook_pmem_map_fileU(uint64_t pool_addr, uint64_t size_addr);
          FunctionType *funcTy = FunctionType::get(
              Type::getVoidTy(ctxt),
              {Type::getInt64Ty(ctxt), Type::getInt64Ty(ctxt)},
              /*IsVarArgs=*/false);

          Value *sizeArg = i_call->getArgOperand(4);

          builder.CreateCall(
              module.getOrInsertFunction("hook_pmem_map_fileU", funcTy),
              {i_call,
               builder.CreatePtrToInt(sizeArg, Type::getInt64Ty(ctxt))});
        }

      } // end if
    } // end for
  } // end inst_pmdk_pmem_region

  void Instrumentor::inst_raw_pmem_region() {

    for (auto &i : instHT) {
      Instruction *inst = i.first;
      if (auto *i_call = dyn_cast<CallInst>(inst)) {
        Function *func = i_call->getCalledFunction();
        if (func == nullptr) {
          // errs() << "[inst_raw_pmem_region] Skip indirect call: " << i_call << "\n";
          continue;
        }

        // open
        if (func->getName().equals("open")) {
          // "open" prototype
          //   int open(const char *pathname, int flags);
          //   int open(const char *pathname, int flags, mode_t mode);
          // errs() << "Found open call: " << func->getName() << "\n";

          // insert after open
          IRBuilder<> builder(i_call->getNextNode());

          // We expect the hook prototype to be:
          //    void hook_open(const char *path, uint32_t fd)
          FunctionType *funcTy = FunctionType::get(
            Type::getVoidTy(ctxt),
            {
              PointerType::getUnqual(Type::getInt8Ty(ctxt)),
              Type::getInt32Ty(ctxt)
            },
            /*IsVarArgs=*/false);

          builder.CreateCall(
            module.getOrInsertFunction("hook_open", funcTy),
            {
              builder.CreatePtrToInt(i_call->getArgOperand(0), Type::getInt64Ty(ctxt)),
              i_call
            });
        }

        // mmap
        else if (func->getName().equals("mmap")) {
          // "mmap" prototype
          //   void *mmap(void *addr, size_t length, int prot, int flags,
          //     int fd, off_t offset);
          // errs() << "Found mmap call: " << func->getName() << "\n";

          // insert after mmap
          IRBuilder<> builder(i_call->getNextNode());

          // We expect the hook prototype to be:
          //    void hook_mmap(uint64_t addr, uint32_t size, uint32_t fd)
          FunctionType *funcTy = FunctionType::get(
            Type::getVoidTy(ctxt),
            {
              Type::getInt64Ty(ctxt),
              // Type::getInt64Ty(ctxt),
              Type::getInt32Ty(ctxt),
              Type::getInt32Ty(ctxt)
            },
            /*IsVarArgs=*/false);

          // i_call->getOperand(0);
          // i_call->getValue()

          builder.CreateCall(
            module.getOrInsertFunction("hook_mmap", funcTy),
            {
              i_call,
              // builder.CreatePtrToInt(i_call->getValue() , Type::getInt64Ty(ctxt)),
              // builder.CreatePtrToInt(i_call->getArgOperand(1), Type::getInt64Ty(ctxt)),
              i_call->getArgOperand(1),
              // builder.CreatePtrToInt(i_call->getArgOperand(4), Type::getInt32Ty(ctxt))
              i_call->getArgOperand(4)
            });
        }
      } // end if
    } // end for
  } // end inst_raw_pmem_region

  // external call related with memory access
  void Instrumentor::handle_external_call() {
    for (auto &i : instHT) {
      Instruction *inst = i.first;
      if (auto *i_call = dyn_cast<CallInst>(inst)) {
        Function *func = i_call->getCalledFunction();
        if (func == nullptr) {
          // errs() << "[handle_external_call] Skip indirect call: " << i_call << "\n";
          continue;
        }

        // memcpy/memmove
        if (std::find(
            MEMCPY_CALLS.begin(), MEMCPY_CALLS.end(), func->getName().str()
          ) != MEMCPY_CALLS.end()) {
          // errs() << "Found memcpy/memmove call: " << func->getName() << "\n";

          IRBuilder<> builder(i_call);

          Value *sizeArg;
          Value *flagsArg;
          if (SIZE_64.find(func->getName().str()) != SIZE_64.end()) {
            // 64-bit size arg
            sizeArg = i_call->getArgOperand(2);
            // sizeArg = builder.CreatePtrToInt(
            //   i_call->getArgOperand(2), Type::getInt64Ty(ctxt));
            flagsArg = builder.getInt32(2);
          } else {
            // 32-bit size arg
            sizeArg = builder.CreateZExt(
              i_call->getArgOperand(2), Type::getInt64Ty(ctxt));
            flagsArg = builder.getInt32(3);
          }

          inst_mem_access(
            /*isStore=*/false, builder, i_call,
            flagsArg,
            ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
            builder.CreatePtrToInt(i_call->getArgOperand(1), Type::getInt64Ty(ctxt)),
            sizeArg
          );

//           builder.CreateCall(
//             module.getOrInsertFunction("hook_mem_read", funcTy),
//             {
//               flagsArg,
//               ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
//               builder.CreatePtrToInt(i_call->getArgOperand(1), Type::getInt64Ty(ctxt)),
//               // builder.CreatePtrToInt(i_call->getArgOperand(2), Type::getInt64Ty(ctxt)),
//               sizeArg,
// #ifdef INST_TRACE_ENABLE
//               msg1,
//               msg2
// #endif
//             });

          // insert after memcpy/memmove func call
          IRBuilder<> store_builder(i_call->getNextNode());
          inst_mem_access(
            /*isStore=*/true, store_builder, i_call,
            flagsArg,
            ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
            store_builder.CreatePtrToInt(i_call->getArgOperand(0), Type::getInt64Ty(ctxt)),
            sizeArg
          );
//           builder.CreateCall(
//             module.getOrInsertFunction("hook_mem_write", funcTy),
//             {
//               flagsArg,
//               ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
//               builder.CreatePtrToInt(i_call->getArgOperand(0), Type::getInt64Ty(ctxt)),
//               // builder.CreatePtrToInt(i_call->getArgOperand(2), Type::getInt64Ty(ctxt)),
//               sizeArg,
// #ifdef INST_TRACE_ENABLE
//               msg1,
//               msg2
// #endif
//             });
        }

        // memset
        else if (std::find(
            MEMSET_CALLS.begin(), MEMSET_CALLS.end(), func->getName().str()
          ) != MEMSET_CALLS.end()) {
          // errs() << "Found memset call: " << func->getName() << "\n";

          // insert after memset func call
          IRBuilder<> builder(i_call->getNextNode());

          Value *sizeArg;
          Value *flagsArg;
          if (SIZE_64.find(func->getName().str()) != SIZE_64.end()) {
            // 64-bit size arg
            sizeArg = i_call->getArgOperand(2);
            // sizeArg = builder.CreatePtrToInt(
            //   i_call->getArgOperand(2), Type::getInt64Ty(ctxt));
            flagsArg = builder.getInt32(4);
          } else {
            // 32-bit size arg
            sizeArg = builder.CreateZExt(
              i_call->getArgOperand(2), Type::getInt64Ty(ctxt));
            flagsArg = builder.getInt32(5);
          }

          inst_mem_access(
            /*isStore=*/true, builder, i_call,
            flagsArg,
            ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
            builder.CreatePtrToInt(i_call->getArgOperand(0), Type::getInt64Ty(ctxt)),
            sizeArg
          );

//           builder.CreateCall(
//             module.getOrInsertFunction("hook_mem_write", funcTy),
//             {
//               flagsArg,
//               ConstantInt::get(Type::getInt64Ty(ctxt), i.second),
//               builder.CreatePtrToInt(i_call->getArgOperand(0), Type::getInt64Ty(ctxt)),
//               // builder.CreatePtrToInt(i_call->getArgOperand(2), Type::getInt64Ty(ctxt)),
//               sizeArg,
// #ifdef INST_TRACE_ENABLE
//               msg1,
//               msg2
// #endif
//             });
        }
      } // end if
    } // end for
  } // end handle_external_call

  void Instrumentor::dump() {
    json j;

    j["functions"] = json::array();
    j["instructions"] = json::array();

    for (auto &f : funcHT) {
      Function *func = f.first;
      j["functions"].push_back({
        {"hash", uint64_t(f.second)},
        {"repr", printRepr(func)}
      });
    }

    for (auto &i : instHT) {
      Instruction *inst = i.first;
      const DebugLoc &loc = inst->getDebugLoc();
      j["instructions"].push_back({
        {"hash", uint64_t(i.second)},
        {"repr", printRepr(inst)},
        {"info", printDebugRepr(&inst->getDebugLoc())}
      });
    }

    // errs() << j.dump(4) << "\n";
    std::ofstream fout(meta_path, std::ios::out | std::ios::trunc);
    if (!fout.is_open()) {
      errs() << "[Instrumentor::dump] can not open " << meta_path << "\n";
      assert(false);
    }

    fout << j.dump(4) << "\n";
    fout.close();
    errs() << "saved instrumentation metadata in " << meta_path << "\n";
  }


} /* namespace racer */