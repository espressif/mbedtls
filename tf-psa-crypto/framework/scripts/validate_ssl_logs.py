#!/usr/bin/env python3
"""Validate logs from ssl_client2 and ssl_server2.

On success, print nothing and return 0.
On a validation failure, print a short error message and return 1.
On a command line or parse error, die with an exception and return 1.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import sys
from typing import Callable, Dict, List, Optional

from mbedtls_framework import ssl_log_parser



# None: validation succeeded.
# str: validation failed; the string is a human-readable explanation of the failure.
Validation = Optional[str]

def match_random(client_log: ssl_log_parser.Info,
                 server_log: ssl_log_parser.Info) -> Validation:
    """Check that both sides have the same idea of client_random and server_random."""
    client_client_randoms = client_log.dumps['client hello, random bytes']
    client_server_randoms = client_log.dumps['server hello, random bytes']
    server_client_randoms = server_log.dumps['client hello, random bytes']
    server_server_randoms = server_log.dumps['server hello, random bytes']
    if len(client_client_randoms) != len(server_client_randoms):
        return ('Client and server disagree on the number of client_random ' +
                f'({len(client_client_randoms)} != {len(server_client_randoms)})')
    if len(client_server_randoms) != len(server_server_randoms):
        return ('Client and server disagree on the number of server_random ' +
                f'({len(client_server_randoms)} != {len(server_server_randoms)})')
    for n, (c, s) in enumerate(zip(client_client_randoms, server_client_randoms)):
        if c != s:
            return f'Client and server disagree on client random #{n}'
    for n, (c, s) in enumerate(zip(client_server_randoms, server_server_randoms)):
        if c != s:
            return f'Client and server disagree on server random #{n}'
    return None


def distinct_server_ephemeral(client_log: ssl_log_parser.Info,
                              _server_log: ssl_log_parser.Info) -> Validation:
    """Check that server ephemeral keys as seen from the client are not repeated."""
    # The current implementation does not handle cases where the client
    # receives and discards a legitimate resend of the ServerKeyExchange
    # message in DTLS.
    if 'DHM: GY' in client_log.dumps:
        values = client_log.dumps['DHM: GY']
    elif 'server ephemeral public key' in client_log.dumps:
        values = client_log.dumps['server ephemeral public key']
    else:
        return 'Ephemeral public keys not found in client log'
    if len(values) < 2:
        return 'Fewer than two server ephemeral public keys found'
    seen = {} #type: Dict[str, int]
    for n, v in enumerate(values):
        if v in seen:
            return f'server ephemeral public key #{n} repeats #{seen[v]}'
        seen[v] = n
    return None

def distinct_server_random(client_log: ssl_log_parser.Info,
                           _server_log: ssl_log_parser.Info) -> Validation:
    """Check that server randoms as seen from the client are not repeated."""
    # The current implementation does not handle cases where the client
    # receives and discards a legitimate resend of the server hello in DTLS.
    values = client_log.dumps['server hello, random bytes']
    if len(values) < 2:
        return 'Fewer than two server_random found'
    def random_part(hex_data: str) -> str:
        # In TLS <=1.2, the first 4 bytes (8 hex digits) are the time,
        # and may differ even if the actually random part is repeated.
        # The last 8 bytes (16 hex digits) are not random in TLS 1.2 when
        # the server also supports 1.3 (they are forced to b'DOWNGR\001').
        return hex_data[8:48]
    seen = {} #type: Dict[str, int]
    for n, v in enumerate(values):
        r = random_part(v)
        if r in seen:
            return f'server_random #{n} repeats #{seen[r]}'
        seen[r] = n
    return None


Task = Callable[[ssl_log_parser.Info, ssl_log_parser.Info], Validation]

TASKS = {
    'distinct_server_ephemeral': distinct_server_ephemeral,
    'distinct_server_random': distinct_server_random,
    'match_random': match_random,
} #type: Dict[str, Task]

def validate(client_log: ssl_log_parser.Info,
             server_log: ssl_log_parser.Info,
             tasks: List[str]) -> Validation:
    """Perform validation tasks on a pair of matching logs.

    Return None if the validation succeeds, a human-oriented error message
    otherwise.
    """
    for task_name in tasks:
        task = TASKS[task_name]
        outcome = task(client_log, server_log)
        if outcome is not None:
            return outcome
    return None


def main() -> int:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list-tasks',
                        action='store_true',
                        help='List available tasks and exit')
    parser.add_argument('client_log', metavar='CLIENT_LOG_FILE',
                        nargs='?',
                        help='Client log file ($CLI_OUT or ?-cli-*.log)')
    parser.add_argument('server_log', metavar='SERVER_LOG_FILE',
                        nargs='?',
                        help='Server log file ($SRV_OUT or ?-srv-*.log)')
    parser.add_argument('tasks', metavar='TASK',
                        nargs='*',
                        help='Tasks to perform (use --list-tasks to see supported task names)')
    args = parser.parse_args()

    if args.list_tasks:
        for task_name in sorted(TASKS.keys()):
            print(task_name)
        return 0

    if args.client_log is None or args.server_log is None:
        parser.error('the following arguments are required: CLIENT_LOG_FILE SERVER_LOG_FILE')
    if not args.tasks:
        parser.error('at least one TASK is required')

    client_log = ssl_log_parser.parse_log_file(args.client_log)
    server_log = ssl_log_parser.parse_log_file(args.server_log)
    outcome = validate(client_log, server_log, args.tasks)
    if outcome is None:
        return 0
    else:
        if outcome and outcome[-1] != '\n':
            outcome += '\n'
        sys.stderr.write(outcome)
        return 1

if __name__ == '__main__':
    sys.exit(main())
