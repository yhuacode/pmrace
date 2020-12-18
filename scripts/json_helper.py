from typing import List, Tuple, Dict

import logging
import json
import re
import pprint

from util import cd, find_all_files

class JsonHelper(object):

    def _scan_folder(self, path: str) -> List[str]:
        json_files = find_all_files(
            path,
            re.compile(r'.*\.json')
        )
        return json_files

    def parse_meta_json(self, path: str, result: Dict) -> None:
        with open(path, 'r') as f:
            data = json.load(f)

        for func in data['functions']:
            logging.debug('{} func: {} {}'.format(path, func, type(func)))
            logging.debug('hash: {} {}'.format(func['hash'], type(func['hash'])))
            func_hval = str(func['hash'])
            logging.debug('hash: {} {}'.format(func['hash'], type(func['hash'])))
            if func_hval in result['functions']:
                logging.debug(func_hval)

            assert func_hval not in result['functions']
            result['functions'][func_hval] = func

        for inst in data['instructions']:
            inst_hval = str(inst['hash'])
            assert inst_hval not in result['instructions']
            result['instructions'][inst_hval] = inst

    def parse_meta_dir_json(self, path: str, result: Dict) -> None:
        json_files = self._scan_folder(path)
        logging.debug('parse_meta_dir_json, files:\n' + pprint.pformat(json_files))
        self._concat(json_files, result)

    def update_json(self, path: str, result: Dict) -> Dict:
        with open(path, 'r') as f:
            data = json.load(f)

        for key, value in data['functions'].items():
            assert key not in result['functions']
            result['functions'][key] = value

        for key, value in data['instructions'].items():
            assert key not in result['instructions']
            result['instructions'][key] = value

        return data

    def _concat(self, files: List[str], result: Dict) -> None:
        for file in files:
            self.parse_meta_json(file, result)

    def concat_json_files(self, in_path: str, out_path: str) -> None:
        result = {'functions': {}, 'instructions': {}}
        self.parse_meta_dir_json(in_path, result)

        with open(out_path, 'w') as f:
            json.dump(result, f, indent=4)


if __name__ == '__main__':
    jh = JsonHelper()
    jh.concat_json_files('/home/lance/Documents/pmrace/deps/pmdk', 'combined.json')