import subprocess
import unittest
from unittest.mock import patch
from image_plan import MissingRef, REPOS, feature_tag, plan, selection, resolve


class ImagePlanTests(unittest.TestCase):
    branch = 'codex/packet-buffer-reuse'

    def resolver(self, branches):
        def lookup(repo, ref):
            if ref != 'main' and repo not in branches:
                raise MissingRef(ref)
            return ('a' if ref == 'main' else 'b') * 40
        return lookup

    def test_manual_feature_combines_all_matching_branches(self):
        result = plan('feature', self.branch, resolve_ref=self.resolver(set(REPOS.values())))
        self.assertEqual(result['tag'], 'testing-packet-buffer-reuse')
        for key in REPOS:
            self.assertEqual(result[key + '_ref'], self.branch)
            self.assertEqual(result[key + '_sha'], 'b' * 40)

    def test_all_partial_feature_combinations_fall_back_only_where_missing(self):
        for mask in range(1, 8):
            present = {repo for i, repo in enumerate(REPOS.values()) if mask & (1 << i)}
            result = plan('feature', self.branch, resolve_ref=self.resolver(present))
            for key, repo in REPOS.items():
                self.assertEqual(result[key + '_ref'], self.branch if repo in present else 'main')

    def test_typo_without_any_matching_branch_fails(self):
        with self.assertRaisesRegex(ValueError, 'No repository'):
            plan('feature', self.branch, resolve_ref=self.resolver(set()))

    def test_main_build_selects_all_main(self):
        result = plan('main', resolve_ref=self.resolver(set()))
        self.assertEqual(result['tag'], 'testing')
        for key in REPOS:
            self.assertEqual(result[key + '_ref'], 'main')

    def test_manual_feature_cannot_overwrite_shared_testing(self):
        with self.assertRaises(ValueError):
            selection('feature', 'main')

    def test_release_uses_tag_and_preserves_pinned_libraries(self):
        calls = []
        def lookup(repo, ref):
            calls.append((repo, ref))
            return 'a' * 40
        result = plan('release', release_tag='v0.4.0', resolve_ref=lookup)
        self.assertEqual(result['tag'], '0.4.0')
        self.assertEqual(result['ipsec_ref'], 'pinned')
        self.assertEqual(result['l2tp_sha'], '')
        self.assertEqual(calls, [(REPOS['app'], 'refs/tags/v0.4.0')])

    def test_network_failure_never_falls_back_to_main(self):
        def lookup(repo, ref):
            raise subprocess.CalledProcessError(128, ['git'])
        with self.assertRaises(subprocess.CalledProcessError):
            plan('feature', self.branch, resolve_ref=lookup)

    def test_lookup_distinguishes_missing_branch_from_network_error(self):
        with patch('image_plan.subprocess.run', side_effect=[subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, stdout='')]):
            with self.assertRaises(MissingRef):
                resolve(REPOS['app'], self.branch)
        with patch('image_plan.subprocess.run', side_effect=subprocess.CalledProcessError(128, ['git'])):
            with self.assertRaises(subprocess.CalledProcessError):
                resolve(REPOS['app'], self.branch)

    def test_invalid_input_rejected(self):
        for mode, branch, tag in [('auto-feature', self.branch, ''), ('feature', '', ''),
                                  ('feature', 'a\nb', ''), ('feature', 'refs/heads/a', ''),
                                  ('release', '', 'v0.4.0-rc1')]:
            with self.subTest(mode=mode, branch=branch, tag=tag), self.assertRaises(ValueError):
                selection(mode, branch, tag)

    def test_simple_tags(self):
        self.assertEqual(feature_tag(self.branch), 'testing-packet-buffer-reuse')
        self.assertEqual(feature_tag('new-auth'), 'testing-new-auth')


if __name__ == '__main__':
    unittest.main()
