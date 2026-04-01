#!/usr/bin/env python3
"""Prepare to release TF-PSA-Crypto or Mbed TLS.

This script constructs a release candidate branch and release artifacts.
It must run from a clean git worktree with initialized, clean git submodules.
When making an Mbed TLS >=4 release, the tf-psa-crypto submodule should
already contain a TF-PSA-Crypto release candidate.
This script will update the checked out git branch, if any.
On normal exit, the worktree contains the release candidate commit.

This script requires the following external tools:
- Git >= 2.40.0 (for ``git archive --mtime=...``).
- GNU tar (can be called ``gnutar`` or ``gtar``);
- ``sha256sum``.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

################################################################

#### Tips for maintainers ####

# This script insists on having a clean git checkout, including
# submodules. If you want to modify it, either make your changes in
# a separate worktree, or commit your changes first and update
# submodules in the parent repositories.

#### Architectural notes ####

# The process of preparing a release consists of some information
# gathering about the branch to release in the `Info` class, then
# a series of steps in `XxxStep` classes.

# Information gathering is performed by the `Info` constructor.
# Any failure causes the script to abort.

# The steps run sequentially in the order defined by `ALL_STEPS`.
# Each step starts by checking precondition in `step.assert_preconditions()`,
# then does its job in `step.run()`. `assert_preconditions` should
# not change any state. `run` is expected to change state and is
# not expected to clean up if an error occurs.

# This script is expected to perform a release reliably, so it
# should try to detect dodgy conditions and abort. It should avoid
# silently outputting garbage. Nonetheless, human review of the
# result is still expected.

# If you add an external dependency to a step, please mention
# it in the docstring at the top.

################################################################


import argparse
import datetime
import os
import pathlib
import re
import subprocess
import sys
import typing
from typing import Callable, Dict, Iterator, List, Optional, Sequence


PathOrString = typing.Union[os.PathLike, str]


class InformationGatheringError(Exception):
    """Problem detected while gathering information."""
    pass


def find_gnu_tar() -> str:
    """Try to guess the command for GNU tar.

    This function never errors out. It defaults to "tar".
    """
    for name in ['gnutar', 'gtar']:
        try:
            subprocess.check_call([name, '--version'],
                                  stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
            return name
        except FileNotFoundError:
            pass
        except subprocess.CalledProcessError:
            pass
    return 'tar'

class Options(typing.NamedTuple):
    """Options controlling the behavior of the release process.

    Each field here should have an associated command line option
    declared in main().
    """
    # Directory where the release artifacts will be placed.
    # If None: "{source_directory}/release-artifacts"
    artifact_directory: Optional[pathlib.Path]
    # Whether to go ahead if submodules are out of date or if there
    # are modified files inside submodules.
    ignore_submodules: bool
    # Release date (YYYY-mm-dd).
    release_date: str
    # Version to release (empty to read it from ChangeLog).
    release_version: str
    # GNU tar command.
    tar_command: str

DEFAULT_OPTIONS = Options(
    artifact_directory=None,
    ignore_submodules=False,
    release_date=datetime.date.today().isoformat(),
    release_version='',
    tar_command=find_gnu_tar())


class Info:
    """Information about the intended release.

    This class contains information gathered from the product tree as well
    as from the command line.
    """


    @staticmethod
    def _git_command(subcommand: List[str],
                     where: Optional[PathOrString] = None) -> List[str]:
        cmd = ['git']
        if where is not None:
            cmd += ['-C', str(where)]
        return cmd + subcommand

    def call_git(self, cmd: List[str],
                 where: Optional[PathOrString] = None) -> None:
        """Run git in the source tree.

        Pass `where` to specify a submodule.
        """
        subprocess.check_call(self._git_command(cmd, where),
                              cwd=self.top_dir)

    def read_git(self, cmd: List[str],
                 where: Optional[PathOrString] = None) -> bytes:
        """Run git in the source tree and return the output.

        Pass `where` to specify a submodule.
        """
        return subprocess.check_output(self._git_command(cmd, where),
                                       cwd=self.top_dir)

    def _read_file_tree(self) -> None:
        """Find information about files in this branch."""
        raw = self.read_git(['submodule', '--quiet',
                             'foreach', '--recursive',
                             'printf %s\\\\0 "$displaypath"'])
        self._submodules = raw.decode('ascii').rstrip('\0').split('\0')

    def _read_product_info(self) -> None:
        """Read product information (name, version) from the source files."""
        with open(self.top_dir / 'ChangeLog', encoding='utf-8') as changelog:
            # We deliberately read only a short portion at the top of the
            # changelog file. This reduces the risk that we'll match an
            # older release if the content near the top of the file doesn't
            # have the expected format.
            head = changelog.read(1000)
            m = re.search(r'^= *(.*?) +([0-9][-.0-9A-Za-z]+) +branch released (\S+)\n',
                          head, re.M)
            if not m:
                raise InformationGatheringError(
                    'Could not find version header line near the top of ChangeLog')
            self._product_human_name = m.group(1)
            self.old_version = m.group(2)
            self.old_release_date = m.group(3)

    @staticmethod
    def _product_machine_name_from_human_name(_human_name: str) -> str:
        """Determine the name used in release tags and file names."""
        if _human_name == 'TF-PSA-Crypto':
            return 'tf-psa-crypto'
        elif _human_name == 'Mbed TLS':
            return 'mbedtls'
        else:
            raise InformationGatheringError(
                f'Could not determine product (found "{_human_name}" in ChangeLog)')

    def __init__(self, top_dir: str, options: Options) -> None:
        """Parse the source files to obtain information about the product.

        Look for the product under `top_dir`.

        Optional parameters can override the supplied information:
        * `version`: version to release.
        """
        self.top_dir = pathlib.Path(top_dir).absolute()
        self._read_file_tree()
        self._read_product_info()
        if options.release_version:
            self._release_version = options.release_version
        else:
            self._release_version = self.old_version
        self._product_machine_name = \
            self._product_machine_name_from_human_name(self._product_human_name)

    @property
    def product_human_name(self) -> str:
        """Human-readable product name, e.g. 'Mbed TLS'."""
        return self._product_human_name

    @property
    def product_machine_name(self) -> str:
        """Machine-friendly product name, e.g. 'mbedtls'."""
        return self._product_machine_name

    @property
    def submodules(self) -> Sequence[str]:
        """Submodules present in the source tree (including nested ones).

        This is a list of paths relative to the root of the main tree.
        Note that the main tree itself is not included.
        """
        return self._submodules

    @property
    def version(self) -> str:
        """Version string for the release."""
        return self._release_version


class Step:
    """A step on the release process.

    This is an abstract class containing some common tooling.
    Subclasses must provide the following methods:
    * `name()` returning a unique name for each step.
    * `run()` doing the work. Raise an exception if something goes wrong.

    Subclasses may override the following methods:
    * `assert_preconditions()` is called to perform sanity checks before
      calling `run()`.
    """

    @classmethod
    def name(cls) -> str:
        """The name of this step."""
        raise NotImplementedError

    def __init__(self, options: Options, info: Info) -> None:
        """Instantiate the release step for the given product directory.

        All step constructors are executed before running the first step.
        """
        self.options = options
        self.info = info
        if options.artifact_directory is None:
            self.artifact_directory = pathlib.Path(self.info.top_dir) / 'release-artifacts'
        else:
            self.artifact_directory = pathlib.Path(options.artifact_directory).absolute()

    def call_git(self, cmd: List[str],
                 where: Optional[PathOrString] = None) -> None:
        """Run git in the source tree.

        Pass `where` to specify a submodule.
        """
        self.info.call_git(cmd, where=where)

    def read_git(self, cmd: List[str],
                 where: Optional[PathOrString] = None) -> bytes:
        """Run git in the source tree and return the output.

        Pass `where` to specify a submodule.
        """
        return self.info.read_git(cmd, where=where)

    def commit_timestamp(self,
                         where: Optional[PathOrString] = None,
                         what: str = 'HEAD') -> int:
        """Return the timestamp (seconds since epoch) of the given commit.

        Pass `where` to specify a submodule.
        Pass `what` to specify a commit (default: ``HEAD``).
        """
        timestamp = self.read_git(['show', '--no-patch', '--pretty=%ct', what],
                                  where=where)
        return int(timestamp)

    def git_index_as_tree_ish(self,
                              where: Optional[PathOrString] = None) -> str:
        """Return a git tree-ish corresponding to the index.

        Pass `where` to specify a submodule.
        """
        raw = self.read_git(['write-tree'], where=where)
        return raw.decode('ascii').strip()

    def commit_datetime(self,
                        where: Optional[PathOrString] = None,
                        what: str = 'HEAD') -> datetime.datetime:
        """Return the time of the given commit.

        Pass `where` to specify a submodule.
        Pass `what` to specify a commit (default: ``HEAD``).
        """
        timestamp = self.commit_timestamp(where=where, what=what)
        return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)

    def assert_git_status(self) -> None:
        """Abort if the working directory is not clean (no git changes).

        This includes git submodules.
        """
        self.call_git(['diff', '--quiet'])

    def files_are_clean(self, *files: str,
                        ignore_submodules: Optional[str] = None,
                        where: Optional[PathOrString] = None) -> bool:
        """Check whether the specified files are identical to their git version.

        With no files, check the whole work tree (including submodules).

        Pass `where` to specify a submodule (default: top level).
        The file names are relative to the repository or submodule root,
        and may not be in a submodule of `where`.
        """
        try:
            cmd = ['diff', '--quiet']
            if ignore_submodules:
                cmd += ['--ignore-submodules=' + ignore_submodules]
            cmd += ['HEAD', '--']
            cmd += list(files)
            self.call_git(cmd, where=where)
            return True
        except subprocess.CalledProcessError as exn:
            if exn.returncode != 1:
                raise
            return False

    def git_commit_maybe(self,
                         files: List[str],
                         message: str) -> None:
        """Commit changes into Git.

        Do nothing if there are no changed files.

        The file names are relative to the toplevel directory,
        and may not be in a submodule.
        """
        if not self.files_are_clean(*files):
            self.call_git(['add', '--'] + files)
            self.call_git(['commit', '--signoff',
                           '-m', message])

    def artifact_base_name(self) -> str:
        """The base name for a release artifact (file created for publishing).

        This contains the product name and version, with no directory part
        or extension. For example "mbedtls-1.2.3".
        """
        return '-'.join([self.info.product_machine_name,
                         self.info.version])

    def artifact_path(self, extension: str) -> pathlib.Path:
        """The path for a release artifact (file created for publishing).

        `extension` should start with a ".".
        """
        file_name = self.artifact_base_name() + extension
        return self.artifact_directory / file_name

    def edit_file(self,
                  path: PathOrString,
                  transform: Callable[[str], str]) -> bool:
        """Edit a text file.

        The path can be relative to the toplevel root or absolute.

        Return True if the file was modified, False otherwise.
        """
        with open(self.info.top_dir / path, 'r+', encoding='utf-8') as file_:
            old_content = file_.read()
            new_content = transform(old_content)
            if old_content == new_content:
                return False
            else:
                file_.seek(0)
                file_.truncate()
                file_.write(new_content)
                return True

    def assert_preconditions(self) -> None:
        """Check whether the preconditions for this step have been achieved.

        If not, raise an exception.
        """
        if self.options.ignore_submodules:
            ignore_submodules = 'all'
        else:
            ignore_submodules = 'none'
        if not self.files_are_clean(ignore_submodules=ignore_submodules):
            raise Exception('There are uncommitted changes (maybe in submodules) in ' +
                            str(self.info.top_dir))

    def run(self) -> None:
        """Perform the release preparation step.

        This may create commits in the source tree or its submodules.
        """
        raise NotImplementedError


class AssembleChangelogStep(Step):
    """Assemble the changelog and commit the result.

    Create a new changelog section if needed.
    Do nothing if the changelog is already fine.

    Note: this step does not check or affect submodules.
    """

    @classmethod
    def name(cls) -> str:
        return 'changelog'

    def create_section(self, old_content: str) -> str:
        """Create a new changelog section for the version that we're releasing."""
        product = self.info.product_human_name
        version = self.info.version
        new_section = f'= {product} {version} branch released xxxx-xx-xx\n\n'
        return re.sub(r'(?=^=)',
                      new_section,
                      old_content, flags=re.MULTILINE, count=1)

    def finalize_release(self, old_content: str) -> str:
        """Update the version and release date in the changelog content."""
        version = self.info.version
        date = self.options.release_date
        return re.sub(r'^(=.* )\S+( branch released )\S+$',
                      rf'\g<1>{version}\g<2>{date}',
                      old_content, flags=re.MULTILINE, count=1)

    def run(self) -> None:
        """Assemble the changelog if needed."""
        subprocess.check_call(['framework/scripts/assemble_changelog.py'],
                              cwd=self.info.top_dir)
        if self.files_are_clean('ChangeLog') and \
           self.info.old_version != self.info.version:
            # Edge case: no change since the previous release.
            # This could happen, for example, in an emergency release
            # of Mbed TLS to ship a crypto bug fix, or when testing
            # the release script.
            self.edit_file('ChangeLog', self.create_section)
        else:
            self.edit_file('ChangeLog', self.finalize_release)
        self.git_commit_maybe(['ChangeLog', 'ChangeLog.d'],
                              'Assemble changelog and set release date')


class BumpVersionStep(Step):
    """Bump the product version and commit the result.

    Do nothing if the product version is already as expected.

    Note: this step does not check or affect submodules.

    Note: this step does not currently handle ABI version bumps,
    only product version bumps.
    """

    @classmethod
    def name(cls) -> str:
        return 'version'

    # Files and directories that may contain version information.
    FILES_WITH_VERSION = [
        'CMakeLists.txt',
        'doxygen',
        'include',
        'tests/suites',
    ]

    def run(self) -> None:
        """Bump the product version if needed."""
        subprocess.check_call(['scripts/bump_version.sh',
                               '--version', self.info.version],
                              cwd=self.info.top_dir)
        self.git_commit_maybe(self.FILES_WITH_VERSION,
                              'Bump version to ' + self.info.version)


class ArchiveStep(Step):
    """Prepare release archives and the associated checksum file."""

    @classmethod
    def name(cls) -> str:
        return 'archive'

    def tar_git_files(self, plain_tar_path: str, prefix: str) -> None:
        """Create an uncompressed tar files with the git contents."""
        # We archive the index, not the commit 'HEAD', because
        # we may have modified some files to turn off GEN_FILES.
        # We do use the commit mtime rather than the current time,
        # however, for reproducibility.
        # A downside of not archiving a commit is that the archive won't
        # contain an extended header with the commit ID that
        # `git get-tar-commit-id` could retrieve. If we change to releasing
        # an exact commit, we should make sure that the commit gets published.
        index = self.git_index_as_tree_ish()
        mtime = self.commit_timestamp()
        # Note that `git archive --mtime=...` requires Git >= 2.40.0.
        self.call_git(['archive', '--format=tar',
                       '--mtime', str(mtime),
                       '--prefix', prefix,
                       '--output', plain_tar_path,
                       index])
        for submodule in self.info.submodules:
            index = self.git_index_as_tree_ish(where=submodule)
            mtime = self.commit_timestamp(where=submodule)
            data = self.read_git(['archive', '--format=tar',
                                  '--mtime', str(mtime),
                                  '--prefix', prefix + submodule + '/',
                                  index],
                                 where=submodule)
            subprocess.run([self.options.tar_command, '--catenate',
                            '-f', plain_tar_path,
                            '/dev/stdin'],
                           input=data,
                           check=True)

    GEN_FILES_FILES = [
        'CMakeLists.txt',
        'tf-psa-crypto/CMakeLists.txt',
    ]

    @staticmethod
    def set_gen_files_default_off(old_content: str) -> str:
        """Make GEN_FILES default off in a build script."""
        # CMakeLists.txt
        new_content = re.sub(r'(option\(GEN_FILES\b.*)\bON\)',
                             r'\g<1>OFF)',
                             old_content)
        return new_content

    def turn_off_gen_files(self) -> None:
        """Make GEN_FILES default off in build scripts."""
        for filename in self.GEN_FILES_FILES:
            path = self.info.top_dir / filename
            if path.exists():
                self.edit_file(path, self.set_gen_files_default_off)
                self.call_git(['add', path.name], where=path.parent)

    def restore_gen_files(self) -> None:
        """Restore build scripts affected by turn_off_gen_files()."""
        for filename in self.GEN_FILES_FILES:
            path = self.info.top_dir / filename
            if path.exists():
                self.call_git(['reset', '--', path.name],
                              where=path.parent)
                self.call_git(['checkout', '--', path.name],
                              where=path.parent)

    @staticmethod
    def list_project_generated_files(project_dir: pathlib.Path) -> List[str]:
        """Return the list of generated files in the given (sub)project.

        The returned file names are relative to the project root.
        """
        raw_list = subprocess.check_output(
            ['framework/scripts/make_generated_files.py', '--list'],
            cwd=project_dir)
        return raw_list.decode('ascii').rstrip('\n').split('\n')

    @staticmethod
    def update_project_generated_files(project_dir: pathlib.Path) -> None:
        """Regenerate the generated files in the given (sub)project."""
        subprocess.check_call(
            ['framework/scripts/make_generated_files.py'],
            cwd=project_dir)

    def tar_add_project_generated_files(self,
                                        plain_tar_path: str,
                                        project_dir: pathlib.Path,
                                        project_prefix: str,
                                        file_list: List[str]) -> None:
        transform = 's/^/' + project_prefix.replace('/', '\\/') + '/g'
        commit_datetime = self.commit_datetime(project_dir)
        file_datetime = commit_datetime + datetime.timedelta(seconds=1)
        subprocess.check_call([self.options.tar_command, '-r',
                               '-f', plain_tar_path,
                               '--transform', transform,
                               '--owner=root:0', '--group=root:0',
                               '--mode=a+rX,u+w,go-w',
                               '--mtime', file_datetime.isoformat(),
                               '--'] + file_list,
                              cwd=project_dir)

    def tar_add_generated_files(self, plain_tar_path: str, prefix: str) -> None:
        """Add generated files to an existing uncompressed tar file."""
        for project in [os.curdir] + list(self.info.submodules):
            if project.endswith('/framework') or project == 'framework':
                continue
            project_dir = self.info.top_dir / project
            project_prefix = (prefix if project == os.curdir else
                              prefix + project + '/')
            gen_script = project_dir / 'framework/scripts/make_generated_files.py'
            # Skip submodules that do not use the framework build machinery.
            if not gen_script.exists():
                continue
            file_list = self.list_project_generated_files(project_dir)
            self.update_project_generated_files(project_dir)
            self.tar_add_project_generated_files(plain_tar_path,
                                                 project_dir,
                                                 project_prefix,
                                                 file_list)

    def create_plain_tar(self, plain_tar_path: str, prefix: str) -> None:
        """Create an uncompressed tar file for the release."""
        self.tar_git_files(plain_tar_path, prefix)
        self.tar_add_generated_files(plain_tar_path, prefix)

    @staticmethod
    def compress_tar(plain_tar_path: str) -> Iterator[str]:
        """Compress the tar file.

        Remove the original, uncompressed file.
        Yield the list of compressed files.
        """
        compressed_path = plain_tar_path + '.bz2'
        if os.path.exists(compressed_path):
            os.remove(compressed_path)
        subprocess.check_call(['bzip2', '-9', plain_tar_path])
        yield compressed_path

    def create_checksum_file(self, archive_paths: List[str]) -> None:
        """Create a checksum file for the given files."""
        checksum_path = self.artifact_path('.txt')
        relative_paths = [os.path.relpath(path, self.artifact_directory)
                          for path in archive_paths]
        content = subprocess.check_output(['sha256sum', '--'] + relative_paths,
                                          cwd=self.artifact_directory,
                                          encoding='ascii')
        with open(checksum_path, 'w') as out:
            out.write(content)

    def run(self) -> None:
        """Create the release artifacts."""
        self.artifact_directory.mkdir(exist_ok=True)
        self.turn_off_gen_files()
        base_name = self.artifact_base_name()
        plain_tar_path = str(self.artifact_path('.tar'))
        self.create_plain_tar(plain_tar_path, base_name + '/')
        compressed_paths = list(self.compress_tar(plain_tar_path))
        self.create_checksum_file(compressed_paths)
        self.restore_gen_files()


class NotesStep(Step):
    """Prepare draft release notes."""

    def __init__(self, options: Options, info: Info) -> None:
        super().__init__(options, info)
        self.checksum_path = self.artifact_path('.txt')

    @classmethod
    def name(cls) -> str:
        return 'notes'

    def assert_preconditions(self) -> None:
        assert self.checksum_path.exists()

    def read_changelog(self) -> Dict[Optional[str], str]:
        """Return the section of the changelog for this release.

        The result is split into categories.
        Use the index None to get the whole content.
        """
        with open(self.info.top_dir / 'ChangeLog', encoding='utf-8') as inp:
            whole_file = inp.read()
            version_iter = re.finditer('^=.*', whole_file, re.MULTILINE)
            start = next(version_iter).end()
            end = next(version_iter).start()
            whole = whole_file[start:end].strip()
        sections = {None: whole} #type: Dict[Optional[str], str]
        headings = [(m.group(), m.start(), m.end())
                    for m in re.finditer(r'^\w.*', whole, re.MULTILINE)]
        for (this, next_) in zip(headings, headings[1:] + [('', -1, -1)]):
            title = this[0]
            start = this[2]
            end = next_[1]
            sections[title] = whole[start:end].strip()
        return sections

    @staticmethod
    def advisory_items(changelog) -> Iterator[str]:
        """Yield the items for the list of advisories."""
        bullets = [m.start()
                   for m in re.finditer(r'^   \* *', changelog, re.MULTILINE)]
        for (this, next_) in zip(bullets, bullets[1:] + [-1]):
            # We don't have the advisory title here, so make up something
            # that the release handler will need to fill in.
            content = changelog[this:next_]
            teaser = re.sub(r'\n.*', '',
                            re.sub(r'^\W*', '', content),
                            re.DOTALL)
            cve_match = re.search(r'CVE-[-0-9]+', content)
            if cve_match:
                cve_text = f' ({cve_match.group(0)})'
            else:
                cve_text = ''
            # We don't have enough data to find the last component of the URL.
            url = 'https://mbed-tls.readthedocs.io/en/latest/security-advisories/'
            yield f'* [{teaser} …{cve_text}]({url})'

    def advisories(self, changelog) -> str:
        """Format links to advisories for the release notes.

        The argument is just the "Security" section of the changelog,
        without its heading.
        """
        items = self.advisory_items(changelog)
        return ('For full details, please see the following links:\n' +
                '[TODO: this section needs manual editing!]\n' +
                '\n'.join(items))

    def notes(self) -> str:
        """Construct draft release notes."""
        changelog = self.read_changelog()
        advisories = (self.advisories(changelog['Security'])
                      if 'Security' in changelog
                      else 'None.')
        with open(self.checksum_path, encoding='ascii') as inp:
            checksums = inp.read()
        # We currently emit a single archive file. If we switch to having
        # multiple files, tweak this definition and the grammar where
        # it's used.
        m = re.search(r'\S+$', checksums)
        if m is None:
            raise Exception('Unable to determine archive file name')
        archive_name = m.group(0)
        # The very long lines here are deliberate. GitHub treats newlines
        # in markdown as line breaks, not as spaces, so an ordinary paragraph
        # needs to be in a single Python logical line.
        return f'''\
## Description

This release of {self.info.product_human_name} provides new features, bug fixes and minor enhancements. \
{'This release includes fixes for security issues.' if 'Security' in changelog else ''}

## Security Advisories

{advisories}

## Release Notes

{changelog[None]}

## Who should update

We recommend all users should update to take advantage of the bug fixes contained in this release at an appropriate point in their development lifecycle.

## Note

:grey_exclamation: `{archive_name}` is our official release file. `source.tar.gz` and `source.zip` are automatically generated snapshots that GitHub is generating. They do not include submodules or generated files, and [cannot be configured](https://github.com/orgs/community/discussions/6003).

## Checksum

The SHA256 hashes for the archives are:
```
{checksums}
```
'''

    def run(self) -> None:
        content = self.notes()
        with open(self.artifact_path('.md'), 'w') as out:
            out.write(content)


ALL_STEPS = [
    AssembleChangelogStep,
    BumpVersionStep,
    ArchiveStep,
    NotesStep,
] #type: Sequence[typing.Type[Step]]


def init_steps(options: Options,
               info: Info,
               #pylint: disable=dangerous-default-value
               step_classes: Sequence[typing.Type[Step]] = ALL_STEPS,
               from_step: Optional[str] = None,
               to_step: Optional[str] = None) -> Sequence[Step]:
    """Initialize the selected steps without running them."""
    steps = [step_class(options, info) for step_class in step_classes]
    if from_step is not None:
        for n, step in enumerate(steps):
            if step.name() == from_step:
                del steps[:n]
                break
        else:
            raise Exception(f'Step name not found: {from_step}')
    if to_step is not None:
        for n, step in enumerate(steps):
            if step.name() == to_step:
                del steps[n+1:]
                break
        else:
            after_msg = f' after {from_step}' if from_step is not None else ''
            raise Exception(f'Step name not found{after_msg}: {to_step}')
    return steps

def run(options: Options,
        top_dir: str,
        from_step: Optional[str] = None,
        to_step: Optional[str] = None) -> None:
    """Run the release process (or a segment thereof)."""
    info = Info(top_dir, options)
    for step in init_steps(options, info, from_step=from_step, to_step=to_step):
        step.assert_preconditions()
        step.run()

def main() -> None:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    # Options that affect information gathering, or that affect the
    # behavior of one or more steps, should have an associated field
    # in the Options class.
    parser.add_argument('--directory', metavar='DIR',
                        default=os.curdir,
                        help='Product toplevel directory (default: .)')
    parser.add_argument('--artifact-directory', '-a', metavar='DIR',
                        help=('Directory where release artifacts will be placed '
                              '(default/empty: <--directory>/release-artifacts)'))
    parser.add_argument('--from-step', '--from', '-f', metavar='STEP',
                        help='First step to run (default: run all steps)')
    parser.add_argument('--ignore-submodules',
                        action='store_true',
                        help='Ignore changes to submodules and changed files within submodules')
    parser.add_argument('--list-steps',
                        action='store_true',
                        help='List release steps and exit')
    parser.add_argument('--only-step', '-s', metavar='STEP',
                        help=('Run only this step (default: run all steps) '
                              '(equivalent to --from-step=STEP --to-step=STEP)'))
    parser.add_argument('--release-date', '-d',
                        help='Release date (YYYY-mm-dd) (default: today)')
    parser.add_argument('--release-version', '-r',
                        help='The version to release (default/empty: from ChangeLog)')
    parser.add_argument('--tar-command',
                        help='GNU tar command')
    parser.add_argument('--to-step', '-t', metavar='STEP',
                        help='Last step to run (default: run all steps)')
    parser.set_defaults(**DEFAULT_OPTIONS._asdict())
    args = parser.parse_args()

    # Process help-and-exit options
    if args.list_steps:
        for step in ALL_STEPS:
            sys.stdout.write(step.name() + '\n')
        return

    if args.only_step:
        args.from_step = args.only_step
        args.to_step = args.only_step
    if args.artifact_directory is None:
        artifact_directory = None
    else:
        artifact_directory = pathlib.Path(args.artifact_directory)
    options = Options(
        artifact_directory=artifact_directory,
        ignore_submodules=args.ignore_submodules,
        release_date=args.release_date,
        release_version=args.release_version,
        tar_command=args.tar_command)

    run(options, args.directory,
        from_step=args.from_step, to_step=args.to_step)

if __name__ == '__main__':
    main()
