#!/usr/bin/env python
"""
Usage:
    preprocess.py [options] TAR_FILES TARGET_FOLDER

Options:
    -h --help                  Show this screen.
    --shard-size=<int>         shard size [default: 3000]
"""

import glob
import multiprocessing
import random
import tarfile
from collections import Iterable
from typing import Tuple
import ujson as json

from docopt import docopt
import os, sys
from multiprocessing import Process
import numpy as np

from utils.ast import SyntaxNode
from utils.code_processing import canonicalize_code, annotate_type, canonicalize_constants
from utils.dataset import Example, json_line_reader
from tqdm import tqdm

all_functions = dict()  # indexed by binaries


def is_valid_example(example):
    return example.ast.size < 300 and \
           len(example.variable_name_map) > 0 and \
           any(k != v for k, v in example.variable_name_map.items())


def example_generator(json_queue, example_queue, consumer_num=1):
    while True:
        payload = json_queue.get()
        if payload is None: break

        examples = []
        for json_str, meta in payload:
            tree_json_dict = json.loads(json_str)

            root = SyntaxNode.from_json_dict(tree_json_dict['ast'])
            # root_reconstr = SyntaxNode.from_json_dict(root.to_json_dict())
            # assert root == root_reconstr

            annotate_type(root)
            canonicalize_constants(root)
            # add function name to the name field of the root block
            root.name = tree_json_dict['function']
            root.named_fields.add('name')

            new_json_dict = root.to_json_dict()
            tree_json_dict['ast'] = new_json_dict
            json_str = json.dumps(tree_json_dict)

            example = Example.from_json_dict(tree_json_dict, binary_file=meta, json_str=json_str)

            if is_valid_example(example):
                canonical_code = canonicalize_code(example.ast.code)
                example.canonical_code = canonical_code
                examples.append(example)

        example_queue.put(examples)

    for i in range(consumer_num):
        example_queue.put(None)

    print('example generator quited!')


def main(args):
    np.random.seed(1234)
    random.seed(1992)

    tgt_folder = args['TARGET_FOLDER']
    tar_files = glob.glob(args['TAR_FILES'])
    print(tar_files)
    shard_size = int(args['--shard-size'])

    os.system(f'mkdir -p {tgt_folder}')
    os.system(f'mkdir -p {tgt_folder}/files')
    num_workers = 14

    for tar_file in tar_files:
        print(f'read {tar_file}')
        valid_example_count = 0

        json_enc_queue = multiprocessing.Queue()
        example_queue = multiprocessing.Queue(maxsize=2000)

        json_loader = multiprocessing.Process(target=json_line_reader,
                                              args=(os.path.expanduser(tar_file), json_enc_queue, num_workers, False, False, 'binary_file'))
        json_loader.daemon = True
        json_loader.start()

        example_generators = []
        for i in range(num_workers):
            p = multiprocessing.Process(target=example_generator, args=(json_enc_queue, example_queue, 1))
            p.daemon = True
            p.start()
            example_generators.append(p)

        n_finished = 0
        while True:
            payload = example_queue.get()
            if payload is None:
                print('received None!')
                n_finished += 1
                if n_finished == num_workers: break
                continue

            examples = payload

            if examples:
                json_file_name = examples[0].binary_file['file_name'].split('/')[-1]
                with open(os.path.join(tgt_folder, 'files/', json_file_name), 'w') as f:
                    for example in examples:
                        f.write(example.json_str + '\n')
                        all_functions.setdefault(json_file_name, dict())[example.ast.compilation_unit] = example.canonical_code

                valid_example_count += len(examples)

        print('valid examples: ', valid_example_count)

        json_enc_queue.close()
        example_queue.close()

        json_loader.join()
        for p in example_generators: p.join()

    cur_dir = os.getcwd()
    all_files = glob.glob(os.path.join(tgt_folder, 'files/*.jsonl'))
    all_files = list(all_files)
    np.random.shuffle(all_files)
    print('Total valid binary file num: ', len(all_files))

    file_num = len(all_files)
    test_file_num = int(file_num * 0.1)
    train_files = all_files[: -2 * test_file_num]
    test_files = all_files[-2 * test_file_num: -test_file_num]
    dev_files = all_files[-test_file_num:]

    train_functions = dict()
    for train_file in train_files:
        file_name = train_file.split('/')[-1]
        for func_name, func in all_functions[file_name].items():
            train_functions.setdefault(func_name, set()).add(func)

    print('dump training files')
    shards = [train_files[i:i + shard_size] for i in range(0, len(train_files), shard_size)]
    for shard_id, shard_files in enumerate(shards):
        print(f'Preparing shard {shard_id}, {len(shard_files)} files: ')
        with open(os.path.join(tgt_folder, 'file_list.txt'), 'w') as f:
            for file_name in shard_files:
                f.write(file_name.split('/')[-1] + '\n')

        os.chdir(os.path.join(tgt_folder, 'files'))
        print('creating tar file...')
        os.system(f'tar cf ../train-shard-{shard_id}.tar -T ../file_list.txt')
        os.chdir(cur_dir)

    def _dump_dev_file(tgt_file_name, file_names):
        with open(os.path.join(tgt_folder, 'file_list.txt'), 'w') as f:
            for file_name in file_names:
                last_file_name = file_name.split('/')[-1]
                f.write(last_file_name + '\n')

                with open(file_name) as fr:
                    all_lines = fr.readlines()

                replace_lines = []
                for line in all_lines:
                    json_dict = json.loads(line.strip())
                    func_name = json_dict['function']
                    canonical_code = all_functions[last_file_name][func_name]
                    func_name_in_train = False
                    func_body_in_train = False
                    if func_name in train_functions:
                        func_name_in_train = True
                        if canonical_code in train_functions[func_name]:
                            func_body_in_train = True

                    json_dict['test_meta'] = dict(function_name_in_train=func_name_in_train,
                                                  function_body_in_train=func_body_in_train)
                    new_json_str = json.dumps(json_dict)
                    replace_lines.append(new_json_str.strip())

                with open(file_name, 'w') as fw:
                    for line in replace_lines:
                        fw.write(line + '\n')

        os.chdir(os.path.join(tgt_folder, 'files'))
        print('creating tar file...')
        os.system(f'tar cf ../{tgt_file_name} -T ../file_list.txt')
        os.chdir(cur_dir)

    print('dump dev files')
    _dump_dev_file('dev.tar', dev_files)
    print('dump test files')
    _dump_dev_file('test.tar', test_files)


if __name__ == '__main__':
    args = docopt(__doc__)
    main(args)