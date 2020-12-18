from typing import List

import sys
import logging

from argparse import ArgumentParser

from fuzz_probe import FuzzProbe
from workload_config import Program, AVALIABLE_PROGRAMS
from util import enable_coloring_in_logging


def main(argv: List[str]) -> int:
    # setup argument parser
    parser = ArgumentParser()

    # logging configs
    parser.add_argument(
        '-v', '--verbose', action='count', default=1,
        help='Verbosity level, can be specified multiple times, default to 1',
    )

    # exe
    parser.add_argument(
        '-e', '--exe', required=True, choices=[x[0] for x in AVALIABLE_PROGRAMS],
        help='The name of program'
    )

    # meta directory
    parser.add_argument(
        '-d', '--dir', default='',
        help='The directory containing instrumented program source code',
    )

    # pmdk path
    parser.add_argument(
        '-p', '--pmdk', default='',
        help=(
            'The directory containing the instrumented source code of PMDK '
            'for PMDK-based applications'
        ),
    )

    # seed directory
    parser.add_argument(
        '-s', '--seeds', default='',
        help='The directory containing input seeds, required for pre-failure fuzzing',
    )

    # interleaving exploration mode
    parser.add_argument(
        '-m', '--mode', default='pmrace', choices=['pmrace', 'random'],
        help='The interleaving exploration mode',
    )
    parser.set_defaults(mode='pmrace')

    # obj.json
    parser.add_argument(
        '--obj-json', dest='obj_json',
        help=(
            '[Unusual option] Provide the path to obj.json to skip the assembling '
            'of json files of PM program to be tested (used for hacking and development)'
        )
    )

    # pmdk.json
    parser.add_argument(
        '--pmdk-json', dest='pmdk_json',
        help=(
            '[Unusual option] Provide the path to pmdk.json to skip the assembling of '
            'PMDK json files (used for hacking and development)'
        )
    )

    # validate
    parser.add_argument(
        '--validate', dest='start_validation', action='store_true',
        help='Filter the bug reports by validation',
    )
    parser.set_defaults(start_validation=False)

    # parse
    args = parser.parse_args(argv)

    # prepare logs
    enable_coloring_in_logging()
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(message)s',
        level=logging.DEBUG
    )

    # set log level for console output
    console = logging.getLogger().handlers[0]
    console.setLevel(logging.WARNING - (logging.DEBUG - logging.NOTSET) * args.verbose)

    seed_dir = args.seeds
    pmdk_path = args.pmdk

    obj_json_path = args.obj_json
    pmdk_json_path = args.pmdk_json
    exploration_mode = args.mode

    program = Program(args.exe, not args.start_validation)
    # obtain the executable from a temporary command, which is generated
    # by default parameters
    if args.start_validation:
        cmd = program.gen_cmd(0, '')
    else:
        cmd = program.gen_cmd(0)
    logging.info("Interleaving exploration strategy: " + exploration_mode)

    executable = cmd[0].rsplit('/', 1)[-1]
    meta_path = 'output/{}.o.json'.format(executable)
    meta_dir = args.dir

    prober = FuzzProbe(
        seed_dir,
        meta_path,
        meta_dir,
        pmdk_path,
        obj_json_path,
        pmdk_json_path,
        exploration_mode
    )

    prober.launch(program, not args.start_validation)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
