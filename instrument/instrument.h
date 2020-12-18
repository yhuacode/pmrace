#ifndef _PMRACE_INSTRUMENT_INSTRUMENT_H_
#define _PMRACE_INSTRUMENT_INSTRUMENT_H_

#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IntrinsicsX86.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Scalar.h" // createLowerAtomicPass

#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <ctime>
#include <cstdlib>
#include <random>

#include "external_call.h"
#include "third-party/json.hpp"

using namespace llvm;
using json = nlohmann::json;

namespace PMRace {

  class PMRacePass : public ModulePass {
  public:
    static char ID;
    // PMRacePass() : ModulePass(ID) {}
    PMRacePass(const std::string &_mode,
      const std::string &_meta_path, const std::string &_race_path,
      const std::string &_unflushed_path, const std::string &_coverage_path);

    PMRacePass();

    virtual bool runOnModule(Module &M) override;

    virtual void print(raw_ostream &os, const Module *m) const override;

    // conservatively think that we changed everything...
    // so, do nothing here
    virtual void getAnalysisUsage(AnalysisUsage &au) const override { }

    virtual StringRef getPassName() const override { return "PMRacePass"; }

  private:
    const std::string mode;
    const std::string meta_path;
    const std::string race_path;
    const std::string unflushed_path;
    const std::string coverage_path;
  };

  class Instrumentor {
  public:
    // TODO: generate different seeds for files with the same name
    Instrumentor(Module &_module, const hash_code &_seed,
      const std::string &_mode,
      const std::string &_meta_path, const std::string &_race_path,
      const std::string &_unflushed_path, const std::string &_coverage_path)
        : module(_module),
          ctxt(module.getContext()),
          seed(_seed),
          mode(_mode),
          meta_path(_meta_path),
          race_path(_race_path),
          unflushed_path(_unflushed_path),
          coverage_path(_coverage_path) { }

    void run();

    ~Instrumentor() = default;
  protected:
    // utils
    bool isBlockHookMark(Instruction *i) {
      // HACK: abuse the donothing intrinsic as the hook mark
      // (see getBlockHookPoint)
      if (!isa<CallInst>(i)) {
        return false;
      }

      Function *f = cast<CallInst>(i)->getCalledFunction();
      if (f == nullptr || !f->isIntrinsic()) {
        return false;
      }

      return f->getIntrinsicID() == Intrinsic::donothing;
    }

    Instruction *getHookedInst(Instruction *i) {
      // follow through and find the first original instruction
      BasicBlock *bb = i->getParent();

      Instruction *c = i;
      while (instHT.find(c) == instHT.end()) {
        c = c->getNextNode();
        assert(c != nullptr && c->getParent() == bb);
      }

      return c;
    }

    Instruction *getBlockHookPoint(BasicBlock *b) {
      Instruction *i = b->getFirstNonPHI();

      // leave LandingPadInst as the first instruction (for Module Verifier)
      if (isa<LandingPadInst>(i)) {
        i = i->getNextNode();
      }

      assert(i != nullptr && i->getParent() == b);

      // first time hooking this basic block, establish the mark
      if (instHT.find(i) != instHT.end()) {
        IRBuilder<> builder(i);
        return builder.CreateIntrinsic(Intrinsic::donothing, {}, {});
      }

      // someone should already placed the mark
      while (!isBlockHookMark(i)) {
        assert(instHT.find(i) == instHT.end());
        i = i->getNextNode();
        assert(i != nullptr && i->getParent() == b);
      }

      return i;
    }

    Instruction *getFunctionEntryPoint(Function *f) {
      /*
       * NOTE: for instrumentations added from entry point,
       *       the instruction order follows the instrumentation order.
       */
      return getBlockHookPoint(&f->getEntryBlock());
    }

    std::vector<Instruction *> getFunctionExitPoints(Function *f) {
      /*
       * NOTE: for instrumentations added from exit points,
       *       the instruction order reverses the instrumentation order.
       */

      std::vector<Instruction *> vec;
      // for (BasicBlock &b : *f) {
      //   Instruction *term = b.getTerminator();
      //   // instrument "return" statement or "exit" function call
      //   if (term != nullptr && (isa<ReturnInst>(term) || isa<UnreachableInst>(term))) {
      //     assert(instHT.find(term) != instHT.end());

      //     Instruction *cur = term, *pre = cur->getPrevNode();
      //     assert(pre != nullptr && pre->getParent() == &b);

      //     while (instHT.find(pre) == instHT.end()) {
      //       // should not go beyond the mark
      //       if (isBlockHookMark(pre)) {
      //         break;
      //       }

      //       cur = pre;
      //       pre = cur->getPrevNode();
      //       assert(pre != nullptr && pre->getParent() == &b);
      //     }

      //     vec.push_back(cur);
      //   }
      // }

      for (inst_iterator it = inst_begin(f); it != inst_end(f); it++) {
        // focus on "return" statement or "exit" function call
        if (!isa<ReturnInst>(*it) && !isa<CallInst>(*it)) {
          continue;
        }

        Instruction *term = &(*it);

        // only instrument call inst for "exit"
        if (auto *i_call = dyn_cast<CallInst>(term)) {
          Function *func = i_call->getCalledFunction();

          if (func == nullptr || !func->getName().equals("exit")) {
            continue;
          }
        }

        assert(instHT.find(term) != instHT.end());
        vec.push_back(term);

      }

      assert(!vec.empty());
      return vec;
    }

  protected:
    // steps in instrumentation
    void prepare();

    // main
    void inst_main();

    // MEM
    void inst_mem_access(
      bool isStore, IRBuilder<> &builder, Instruction *inst,
      Value *flags, Value *hval, Value *addr, Value *size
    );

    void iter_inst();

    // CFG
    void inst_branch_enter();

    // PMEM region
    void inst_pmdk_pmem_region();
    void inst_raw_pmem_region();

    // external call related with memory access
    void handle_external_call();

    void dump();

    Module &module;
    LLVMContext &ctxt;

    // seed for instrumentation
    hash_code seed;

    std::map<Function *, hash_code> funcHT;  // instrumentable functions
    std::map<BasicBlock *, hash_code> blockHT;  // instrumentable basic blocks
    std::map<Instruction *, hash_code> instHT;  // instrumentable instructions

    // cache line flushes and memory fences
    std::map<Function *, hash_code> persistHT;  // persistency functions/intrinsincs

    const std::string mode;

    const std::string meta_path;
    const std::string race_path;
    const std::string unflushed_path;
    const std::string coverage_path;

  private:
    void printFunction(const Function *f, raw_string_ostream &stm) {
      if (f->isDeclaration()) {
        stm << "declare ";
      } else {
        stm << "define ";
      }

      FunctionType *ft = f->getFunctionType();
      ft->getReturnType()->print(stm);
      stm << " @";

      if (f->hasName()) {
        stm << f->getName();
      } else {
        stm << "<anon>";
      }

      stm << "(";
      for (auto &arg : f->args()) {
        if (arg.getArgNo() != 0) {
          stm << ", ";
        }
        arg.print(stm);
      }
      stm << ")";
    }

    void printBasicBlock(const BasicBlock *b, raw_string_ostream &stm) {
      const Function *f = b->getParent();

      unsigned bseq = 0, iseq = 0;
      for (const BasicBlock &bb : *f) {
        if (&bb == b) {
          break;
        }
        bseq += 1;
        iseq += bb.size();
      }

      if (b->hasName()) {
        stm << b->getName();
      } else {
        stm << "<label>";
      }
      stm << ": " << bseq << " | " << iseq;
    }

    std::string printRepr(const Value *v) {
      std::string str;
      raw_string_ostream stm(str);

      if (auto *p_func = dyn_cast<Function>(v)) {
        stm << "function: ";
        printFunction(p_func, stm);
      } else if (auto *p_bb = dyn_cast<BasicBlock>(v)) {
        stm << "basic block: ";
        printBasicBlock(p_bb, stm);
      } else {
        v->print(stm);
      }

      stm.flush();
      return str;
    }

    std::string printDebugRepr(const DebugLoc *d) {
      std::string str;
      raw_string_ostream stm(str);

      d->print(stm);

      stm.flush();
      return str;
    }
  };

} /* namespace pmrace */

#endif /* _PMRACE_INSTRUMENT_INSTRUMENT_H_ */