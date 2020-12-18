#include "instrument.h"

namespace PMRace{

  // Pass info
  char PMRacePass::ID = 0; // LLVM ignores the actual value
  static RegisterPass<PMRacePass> X("PMRacePass", "An example pass",
                                    false /* Only looks at CFG */,
                                    false /* Analysis Pass */);
  // options
  cl::opt<std::string> opt_pmrace_mode("pmrace-mode",
                        cl::Required,
                        cl::desc("<mode of PM instrumentation, {raw,pmdk}>"));
  cl::opt<std::string> opt_meta_out_path("meta-path",
                        cl::Required,
                        cl::desc("<output path of metadata>"));
  cl::opt<std::string> opt_race_out_path("race-path",
                        cl::Required,
                        cl::desc("<output path of race pairs>"));
  cl::opt<std::string> opt_unflushed_out_path("unflushed-path",
                        cl::Required,
                        cl::desc("<output path of unflushed data>"));
  cl::opt<std::string> opt_coverage_out_path("coverage-path",
                        cl::Required,
                        cl::desc("<output path of coverage incr>"));

  PMRacePass::PMRacePass(
    const std::string &_mode,
    const std::string &_meta_path,
    const std::string &_race_path,
    const std::string &_unflushed_path,
    const std::string &_coverage_path)
      : ModulePass(ID), mode(_mode),
        meta_path(_meta_path), race_path(_race_path),
        unflushed_path(_unflushed_path), coverage_path(_coverage_path)
  {}

  PMRacePass::PMRacePass()
    : PMRacePass(
      opt_pmrace_mode.getValue(),
      opt_meta_out_path.getValue(),
      opt_race_out_path.getValue(),
      opt_unflushed_out_path.getValue(),
      opt_coverage_out_path.getValue())
  {
  }

  bool PMRacePass::runOnModule(Module &M) {
    std::string seed;
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, sizeof(alphanum) - 1);

    int random_len = 10;
    for (int i = 0; i < random_len; ++i) {
        seed += alphanum[dist(rng)];
    }
    // errs() << "In module called: " << M.getName();
    seed += M.getName().str();
    // errs() << ", random string: " << seed;
    hash_code seed_value = hash_value(seed);
    // errs() << ", seed value: " << seed_value << "\n";

    Instrumentor instrumentor(
      M, seed_value, mode, meta_path, race_path, unflushed_path, coverage_path);
    instrumentor.run();

    return true;
  }

  void PMRacePass::print(raw_ostream &os, const Module *m) const {
    os << "PMRacePass completed on " << m->getName() << "\n";
  }

  // Pass loading stuff
  // To use, run: clang -Xclang -load -Xclang <your-pass>.so <other-args> ...

  //Automatically enable the pass.
  //http://adriansampson.net/blog/clangpass.html
  static void registerPMRacePass(const PassManagerBuilder &,
                      legacy::PassManagerBase &PM) {
      // Unlike KLEE, we can't lower atomic instructions with non-atomic operations
      // PM.add(createLowerAtomicPass());

      PM.add(new PMRacePass());
  }

  // These constructors add our pass to a list of global extensions.
  static RegisterStandardPasses
    clangtoolLoader_Ox(PassManagerBuilder::EP_OptimizerLast, registerPMRacePass);
  static RegisterStandardPasses
    clangtoolLoader_O0(PassManagerBuilder::EP_EnabledOnOptLevel0, registerPMRacePass);

  // Note: The location EP_OptimizerLast places this pass at the end of the list
  // of *optimizations*. That means on -O0, it does not get run.
  //
  // In general, adding your pass twice will cause it to run twice, but in this
  // particular case, the two are disjoint (EP_EnabledOnOptLevel0 only runs if
  // you're in -O0, and EP_OptimizerLast only runs if you're not). You can check
  // include/llvm/Transforms/IPO/PassManagerBuilder.h header and
  // lib/Transforms/IPO/PassManagerBuilder.cpp file for the exact behavior.

} /* namespace racer */