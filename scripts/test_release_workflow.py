#!/usr/bin/env python3
"""Offline regression tests for the maintained cargo-dist workflow (stdlib only).

Execute the actual inline Bash with fake gh/dist/jq, never release operations.
The indentation helpers intentionally recognize our checked-in workflow layout,
not arbitrary YAML; a layout change must update these tests rather than skip it.
"""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
RELEASE = (ROOT / '.github/workflows/release.yml').read_text()
VALIDATOR = (ROOT / '.github/workflows/release-tag-check.yml').read_text()


def job(source, name):
    match = re.search(rf'^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:\n|\Z)',
                      source, re.M | re.S)
    if not match:
        raise AssertionError(f'missing job {name}')
    return match[1]


def run_blocks(source):
    lines = source.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r'^( +)run: (.*)$', line)
        if not match:
            continue
        if match[2] not in ('|', '>'):
            yield match[2]
            continue
        body = []
        for following in lines[index + 1:]:
            if following.strip() and len(following) - len(following.lstrip()) <= len(match[1]):
                break
            body.append(following)
        yield textwrap.dedent('\n'.join(body))


def script(source, step):
    marker = f'      - {step}\n'
    if source.count(marker) != 1:
        raise AssertionError(f'expected exactly one step: {step}')
    return next(run_blocks(source.split(marker)[1]))


def assert_boundaries(test, release):
    # Catch regeneration restoring any raw tag expression, including downstream
    # outputs (double-quoting an Actions expression does NOT prevent injection).
    for body in run_blocks(release):
        test.assertNotRegex(body, r'\$\{\{[^}]*\b(?:tag|tag-flag)\b[^}]*}}')
    plan = job(release, 'plan')
    test.assertIn('    needs: custom-release-tag-check\n', plan)
    for key in ('tag', 'publishing'):
        test.assertIn(f'      {key}: ${{{{ needs.custom-release-tag-check.outputs.{key} }}}}', plan)
    test.assertIn('RELEASE_TAG: ${{ needs.custom-release-tag-check.outputs.tag }}', plan)
    test.assertIn('RELEASE_PUBLISHING: ${{ needs.custom-release-tag-check.outputs.publishing }}', plan)
    for name in ('build-local-artifacts', 'build-global-artifacts', 'host'):
        test.assertIn('RELEASE_TAG: ${{ needs.plan.outputs.tag }}', job(release, name))
    host = job(release, 'host')
    test.assertIn('      - custom-release-tag-check\n', host)
    test.assertIn("needs.custom-release-tag-check.result == 'success'", host)
    test.assertIn("needs.plan.result == 'success'", host)
    test.assertIn("needs.plan.outputs.publishing == 'true'", host)


class ReleaseBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='attached-release-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        bindir = self.root / 'bin'
        bindir.mkdir()
        # All tools capable of a release/API operation are fake, even when a
        # future workflow regression would mistakenly invoke them.
        mock = f'#!{sys.executable}\n' + textwrap.dedent('''\
            import json, os, sys
            from pathlib import Path
            tool = Path(sys.argv[0]).name
            if tool == 'jq':
                if '--raw-output' not in sys.argv:
                    print('{"upload_files":[]}')
                sys.exit(0)
            with open(os.environ['CALLS'], 'a') as log:
                log.write(json.dumps([tool, *sys.argv[1:]]) + '\\n')
            if tool == 'gh':
                if os.environ.get('GH_FAIL') == '1':
                    sys.exit(1)
                print(os.environ['FAKE_COMMIT'])
            else:
                print('{"upload_files":[]}')
            ''')
        for name in ('gh', 'dist', 'jq'):
            path = bindir / name
            path.write_text(mock)
            path.chmod(0o700)
        (self.root / 'target/distrib').mkdir(parents=True)
        (self.root / 'artifacts').mkdir()
        (self.root / 'artifacts/synthetic.txt').write_text('not a release artifact')
        self.env = {
            'PATH': f'{bindir}:/usr/bin:/bin', 'HOME': str(self.root),
            'CALLS': str(self.root / 'calls.jsonl'), 'RUNNER_TEMP': str(self.root),
            'GITHUB_OUTPUT': str(self.root / 'outputs.txt'),
            'GITHUB_REPOSITORY': 'test/repository',
            'RELEASE_EVENT': 'workflow_dispatch', 'RELEASE_REF': 'refs/heads/main',
            'RELEASE_COMMIT': 'a' * 40, 'FAKE_COMMIT': 'a' * 40,
            'RELEASE_TAG': 'v1.2.3', 'RELEASE_PUBLISHING': 'true',
            'BUILD_MANIFEST_NAME': 'target/distrib/test-manifest.json',
            'ANNOUNCEMENT_TITLE': 'test', 'ANNOUNCEMENT_BODY': 'test', 'PRERELEASE_FLAG': '',
        }

    def run_script(self, body, **env):
        # Only a trusted, fixed matrix flag is substituted by this offline test.
        body = body.replace('${{ matrix.dist_args }}', '--artifacts=local')
        self.assertNotIn('${{', body)
        Path(self.env['CALLS']).write_text('')
        Path(self.env['GITHUB_OUTPUT']).write_text('')
        result = subprocess.run(['/bin/bash', '-e', '-u', '-o', 'pipefail', '-c', body],
                                env={**self.env, **env}, cwd=self.root,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5)
        calls = [json.loads(line) for line in Path(self.env['CALLS']).read_text().splitlines()]
        # Only scalar outputs are relevant here; artifact jobs also emit paths<<EOF.
        outputs = dict(line.split('=', 1) for line in Path(self.env['GITHUB_OUTPUT']).read_text().splitlines()
                       if '=' in line)
        self.assertFalse((self.root / 'INJECTED').exists(), result)
        return result, calls, outputs

    def validate(self, **env):
        return self.run_script(script(VALIDATOR, 'id: validate'), **env)

    def test_invalid_dispatch_inputs_fail_before_api_or_release_operations(self):
        for tag in ('', 'v1.2', '1.2.3', 'v01.2.3', 'v1.2.3-rc.1', 'v1.2.3+build',
                    'v1.2.3 ', 'v1.2.3\n', 'v1.2.3\r', '--help', 'v１.2.3',
                    'v1.2.3$(touch INJECTED)', 'v1.2.3`touch INJECTED`',
                    'v1.2.3;touch INJECTED', 'v1.2.3\ntouch INJECTED',
                    'v1.2.3";touch INJECTED;#', "v1.2.3';touch INJECTED;#",
                    'dry-run$(touch INJECTED)'):
            with self.subTest(tag=tag):
                result, calls, outputs = self.validate(RELEASE_TAG=tag)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
                self.assertEqual(outputs, {})

    def test_stable_tag_requires_matching_commit(self):
        for tag in ('v0.0.0', 'v1.2.3', 'v123.45.6'):
            with self.subTest(tag=tag):
                result, calls, outputs = self.validate(RELEASE_TAG=tag)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [['gh', 'api', f'repos/test/repository/commits/{tag}', '--jq', '.sha']])
                self.assertEqual(outputs, {'tag': tag, 'publishing': 'true'})
        for overrides in ({'FAKE_COMMIT': 'b' * 40}, {'GH_FAIL': '1'}):
            result, calls, outputs = self.validate(**overrides)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 1)
            self.assertEqual(outputs, {})

    def test_ref_cannot_bypass_validation(self):
        for overrides in ({'RELEASE_REF': 'refs/tags/v9.9.9'},
                          {'RELEASE_REF': 'refs/pull/1/merge', 'RELEASE_TAG': 'bad'},
                          {'RELEASE_EVENT': 'push'},
                          {'RELEASE_EVENT': 'pull_request', 'RELEASE_TAG': 'v1.2.3'}):
            result, calls, outputs = self.validate(**overrides)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, [])
            self.assertEqual(outputs, {})

    def test_pull_request_and_dry_run_plan_without_hosting(self):
        for overrides in ({'RELEASE_EVENT': 'pull_request', 'RELEASE_TAG': '',
                           'RELEASE_REF': 'refs/pull/1/merge'}, {'RELEASE_TAG': 'dry-run'}):
            result, calls, outputs = self.validate(**overrides)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls, [])
            self.assertEqual(outputs, {'tag': '', 'publishing': 'false'})
            result, calls, _ = self.run_script(script(job(RELEASE, 'plan'), 'id: plan'),
                                              RELEASE_TAG=outputs['tag'], RELEASE_PUBLISHING=outputs['publishing'])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls, [['dist', 'plan', '--output-format=json']])

    def test_publish_plan_and_missing_mode(self):
        result, _, outputs = self.validate()
        self.assertEqual(result.returncode, 0)
        body = script(job(RELEASE, 'plan'), 'id: plan')
        result, calls, _ = self.run_script(body, RELEASE_TAG=outputs['tag'], RELEASE_PUBLISHING=outputs['publishing'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [['dist', 'host', '--steps=create', '--tag=v1.2.3', '--output-format=json']])
        result, calls, _ = self.run_script(body, RELEASE_PUBLISHING='')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_all_tag_sinks_keep_even_unvalidated_strings_as_single_argv_data(self):
        # Bypass validation deliberately to test the second defense: no shell
        # evaluation, word splitting, or extra option injection at ANY tag sink.
        sinks = [('plan', 'id: plan'), ('build-local-artifacts', 'name: Build artifacts'),
                 ('build-global-artifacts', 'id: cargo-dist'), ('host', 'id: host'),
                 ('host', 'name: Create GitHub Release')]
        for name, step in sinks:
            for tag in ('v1.2.3$(touch INJECTED)', 'v1.2.3`touch INJECTED`',
                        'v1.2.3;touch INJECTED', 'v1.2.3\ntouch INJECTED',
                        'v1.2.3" --evil-option', "v1.2.3' --evil-option"):
                with self.subTest(job=name, step=step, tag=tag):
                    result, calls, _ = self.run_script(script(job(RELEASE, name), step), RELEASE_TAG=tag)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(calls), 1)
                    expected = tag if calls[0][0] == 'gh' else '--tag=' + tag
                    self.assertIn(expected, calls[0])
                    self.assertNotIn('--evil-option', calls[0])

    def test_dry_run_builds_omit_tag_flag(self):
        for name, step in (('build-local-artifacts', 'name: Build artifacts'),
                           ('build-global-artifacts', 'id: cargo-dist')):
            result, calls, _ = self.run_script(script(job(RELEASE, name), step), RELEASE_TAG='')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls[0][:2], ['dist', 'build'])
            self.assertFalse(any(arg.startswith('--tag') for arg in calls[0]))

    def test_maintained_customization_is_guarded_against_regeneration(self):
        assert_boundaries(self, RELEASE)
        config = tomllib.loads((ROOT / 'dist-workspace.toml').read_text())['dist']
        self.assertEqual(config['cargo-dist-version'], '0.32.0')
        self.assertEqual(config['allow-dirty'], ['ci'])
        self.assertIn('permissions:\n  contents: read\n', VALIDATOR)
        for key in ('tag', 'publishing'):
            self.assertIn(f'value: ${{{{ jobs.validate.outputs.{key} }}}}', VALIDATOR)
            self.assertIn(f'{key}: ${{{{ steps.validate.outputs.{key} }}}}', VALIDATOR)
        check = (ROOT / '.github/workflows/release-input-check.yml').read_text()
        self.assertIn('run: python3 scripts/test_release_workflow.py', check)
        self.assertIn('.github/workflows/release*.yml', check)
        # Demonstrate that restoring cargo-dist's unsafe defaults fails the guard.
        for unsafe in (RELEASE.replace('    needs: custom-release-tag-check\n', ''),
                       RELEASE.replace('"--tag=$RELEASE_TAG"', '${{ inputs.tag }}')):
            with self.assertRaises(AssertionError):
                assert_boundaries(self, unsafe)


if __name__ == '__main__':
    unittest.main(verbosity=2)
