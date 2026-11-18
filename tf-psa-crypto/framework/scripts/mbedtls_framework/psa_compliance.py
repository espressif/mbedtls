"""Run the PSA Crypto API compliance test suite.

Clone the psa-arch-tests repo and check out the specified commit.
The clone is stored at <repository root>/psa-arch-tests.
Check out the commit specified by the calling script and apply patches if needed.
Compile the library and the compliance tests and run the test suite.

The calling script can specify a list of expected failures.
Unexpected failures and successes are reported as errors, to help
keep the list of known defects as up to date as possible.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import os
import re
import shutil
import subprocess
import sys
from typing import List, Optional
from pathlib import Path

from . import build_tree

PSA_ARCH_TESTS_REPO = 'https://github.com/ARM-software/psa-arch-tests.git'

#pylint: disable=too-many-arguments,too-many-branches,too-many-statements,too-many-locals
def test_compliance(library_build_dir: str,
                    psa_arch_tests_repo: str,
                    psa_arch_tests_ref: str,
                    patch_files: List[Path],
                    psa_arch_tests_dir: str,
                    expected_failures: List[int]) -> int:
    """Check out and run compliance tests.

    library_build_dir: path where our library will be built.
    psa_arch_tests_ref: tag or sha to use for the arch-tests
                        (empty=default/leave alone).
    patch_files: patches (list of file names) to apply to the arch-tests
                 with ``patch -p1`` (not if psa_arch_tests_ref is empty).
    expected_failures: default list of expected failures.
    """
    root_dir = os.getcwd()
    install_dir = Path(library_build_dir + "/install_dir").resolve()
    tmp_env = os.environ
    tmp_env['CC'] = 'gcc'
    subprocess.check_call(['cmake', '.', '-GUnix Makefiles',
                           '-B' + library_build_dir,
                           '-DENABLE_TESTING=Off', '-DENABLE_PROGRAMS=Off',
                           '-DCMAKE_INSTALL_PREFIX=' + str(install_dir)],
                          env=tmp_env)
    subprocess.check_call(['cmake', '--build', library_build_dir, '--target', 'install'])

    if build_tree.is_mbedtls_3_6():
        crypto_library_path = install_dir.joinpath("lib/libmbedcrypto.a")
    else:
        crypto_library_path = install_dir.joinpath("lib/libtfpsacrypto.a")

    os.makedirs(psa_arch_tests_dir, exist_ok=True)
    try:
        os.chdir(psa_arch_tests_dir)

        # Reuse existing working copy if psa_arch_tests_ref is empty.
        # Otherwise check out and patch the specified ref.
        if psa_arch_tests_ref:
            # Reuse existing local clone
            if not os.path.exists('.git'):
                subprocess.check_call(['git', 'init'])
            subprocess.check_call(['git', 'fetch', psa_arch_tests_repo, psa_arch_tests_ref])

            subprocess.check_call(['git', 'checkout', '--force', 'FETCH_HEAD'])
            subprocess.check_call(['git', 'reset', '--hard'])
            for patch_file in patch_files:
                with open(os.path.join(root_dir, patch_file), 'rb') as patch:
                    subprocess.check_call(['patch', '-p1'],
                                          stdin=patch)

        build_dir = 'api-tests/build'
        try:
            shutil.rmtree(build_dir)
        except FileNotFoundError:
            pass
        os.mkdir(build_dir)
        os.chdir(build_dir)

        #pylint: disable=bad-continuation
        subprocess.check_call([
            'cmake', '..',
                     '-GUnix Makefiles',
                     '-DTARGET=tgt_dev_apis_stdc',
                     '-DTOOLCHAIN=HOST_GCC',
                     '-DSUITE=CRYPTO',
                     '-DPSA_CRYPTO_LIB_FILENAME={}'.format(str(crypto_library_path)),
                     '-DPSA_INCLUDE_PATHS=' + str(install_dir.joinpath("include"))
        ])

        subprocess.check_call(['cmake', '--build', '.'])

        proc = subprocess.Popen(['./psa-arch-tests-crypto'],
                                bufsize=1,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                universal_newlines=True)

        test_re = re.compile(
            '^TEST: (?P<test_num>[0-9]*)|'
            '^TEST RESULT: (?P<test_result>FAILED|PASSED)'
        )
        test = -1
        unexpected_successes = set(expected_failures)
        seen_expected_failures = set()
        unexpected_failures = set()
        if proc.stdout is None:
            return 1

        for line in proc.stdout:
            print(line, end='')
            match = test_re.match(line)
            if match is not None:
                groupdict = match.groupdict()
                test_num = groupdict['test_num']
                if test_num is not None:
                    test = int(test_num)
                elif groupdict['test_result'] == 'FAILED':
                    if test in unexpected_successes:
                        unexpected_successes.remove(test)
                        seen_expected_failures.add(test)
                        print('Expected failure, ignoring')
                    else:
                        unexpected_failures.add(test)
                        print('ERROR: Unexpected failure')
                elif test in unexpected_successes:
                    print('ERROR: Unexpected success')
        proc.wait()

        print()
        print('***** test_psa_compliance.py report ******')
        print()
        print('Expected failures:', ', '.join(str(i) for i in sorted(seen_expected_failures)))
        print('Unexpected failures:', ', '.join(str(i) for i in sorted(unexpected_failures)))
        print('Unexpected successes:', ', '.join(str(i) for i in sorted(unexpected_successes)))
        print()
        if unexpected_successes or unexpected_failures:
            if unexpected_successes:
                print('Unexpected successes encountered.')
                print('Please remove the corresponding tests from '
                      'EXPECTED_FAILURES in tests/scripts/compliance_test.py')
                print()
            print('FAILED')
            return 1
        else:
            print('SUCCESS')
            return 0
    finally:
        os.chdir(root_dir)

def main(psa_arch_tests_ref: str,
         expected_failures: Optional[List[int]] = None) -> None:
    """Command line entry point.

    psa_arch_tests_ref: tag or sha to use for the arch-tests.
    expected_failures: default list of expected failures.
    """
    default_patch_directory = os.path.join(build_tree.guess_project_root(),
                                           'scripts/data_files/psa-arch-tests')

    # pylint: disable=invalid-name
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir',
                        default='out_of_source_build',
                        help=('path to Mbed TLS / TF-PSA-Crypto build directory '
                              '(default: %(default)s)'))
    parser.add_argument('--expected-failures', nargs='+',
                        help='''set the list of test codes which are expected to fail
                                from the command line. If omitted the list given by
                                EXPECTED_FAILURES (inside the script) is used.''')
    parser.add_argument('--patch-directory', nargs=1,
                        default=default_patch_directory,
                        help=('Directory containing patches (*.patch) to apply '
                              'to psa-arch-tests (default: %(default)s)'))
    parser.add_argument('--tests-dir', metavar='DIR',
                        default='psa-arch-tests',
                        help=('path to psa-arch-tests build directory '
                              '(default: %(default)s)'))
    parser.add_argument('--tests-ref', metavar='REF',
                        default=psa_arch_tests_ref,
                        help=('Commit (tag/branch/sha) to use for psa-arch-tests '
                              '(empty to use whatever is there and skip patching) '
                              '(default: %(default)s)'))
    parser.add_argument('--tests-repo', metavar='URL',
                        default=PSA_ARCH_TESTS_REPO,
                        help=('Repository to clone for psa-arch-tests '
                              '(default: %(default)s)'))
    args = parser.parse_args()

    if expected_failures is None:
        expected_failures = []
    if args.expected_failures is not None:
        expected_failures_list = [int(i) for i in args.expected_failures]
    else:
        expected_failures_list = expected_failures

    if args.patch_directory:
        patch_files = sorted(Path(args.patch_directory).glob('*.patch'))
    else:
        patch_files = []

    sys.exit(test_compliance(args.build_dir,
                             args.tests_repo,
                             args.tests_ref,
                             patch_files,
                             args.tests_dir,
                             expected_failures_list))
