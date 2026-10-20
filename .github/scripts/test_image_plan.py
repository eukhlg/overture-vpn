import subprocess
import unittest
from unittest.mock import patch
from image_plan import MissingRef, REPOS, feature_tag, plan, selection, resolve


class ImagePlanTests(unittest.TestCase):
    def test_three_independent_branches_are_used_exactly(self):
        calls = []
        def lookup(repo, ref):
            calls.append((repo, ref))
            return {'eukhlg/overture-vpn': 'a', 'eukhlg/l2tp-go': 'b', 'eukhlg/ipsec-go': 'c'}[repo] * 40
        result = plan('feature', 'app-feature', resolve_ref=lookup,
                      l2tp_branch='l2tp-feature', ipsec_branch='ipsec-feature')
        self.assertEqual(calls, [(REPOS['app'], 'app-feature'), (REPOS['l2tp'], 'l2tp-feature'), (REPOS['ipsec'], 'ipsec-feature')])
        self.assertEqual(result['app_sha'], 'a' * 40)
        self.assertEqual(result['l2tp_sha'], 'b' * 40)
        self.assertEqual(result['ipsec_sha'], 'c' * 40)
        self.assertEqual(result['l2tp_ref'], 'l2tp-feature')

    def test_missing_selected_branch_never_falls_back(self):
        calls = []
        def lookup(repo, ref):
            calls.append((repo, ref))
            if repo == REPOS['l2tp']:
                raise MissingRef('missing selected L2TP branch')
            return 'a' * 40
        with self.assertRaises(MissingRef):
            plan('feature', 'app-feature', resolve_ref=lookup,
                 l2tp_branch='missing', ipsec_branch='other')
        self.assertEqual(calls, [(REPOS['app'], 'app-feature'), (REPOS['l2tp'], 'missing')])

    def test_explicit_main_selections_are_supported(self):
        result = plan('feature', 'main', resolve_ref=lambda repo, ref: 'a' * 40)
        self.assertEqual(result['tag'], 'testing-main')
        for component in REPOS:
            self.assertEqual(result[component + '_ref'], 'main')

    def test_optional_image_name_does_not_affect_source_selection(self):
        result = plan('feature', 'main', resolve_ref=lambda repo, ref: 'a' * 40,
                      l2tp_branch='buffer-api', ipsec_branch='udp', image_name='udp-batching')
        self.assertEqual(result['tag'], 'testing-udp-batching')
        self.assertEqual(result['app_ref'], 'main')
        self.assertEqual(result['l2tp_ref'], 'buffer-api')
        self.assertEqual(result['ipsec_ref'], 'udp')

    def test_auto_main_ignores_manual_selectors(self):
        calls = []
        def lookup(repo, ref):
            calls.append(ref)
            return 'a' * 40
        result = plan('main', 'feature', resolve_ref=lookup,
                      l2tp_branch='other', ipsec_branch='another', image_name='ignored')
        self.assertEqual(result['tag'], 'testing')
        self.assertEqual(calls, ['main', 'main', 'main'])

    def test_release_uses_tag_and_pinned_dependencies(self):
        calls = []
        def lookup(repo, ref):
            calls.append((repo, ref))
            return 'a' * 40
        result = plan('release', release_tag='v0.4.0', resolve_ref=lookup)
        self.assertEqual(result['tag'], '0.4.0')
        self.assertEqual(result['ipsec_ref'], 'pinned')
        self.assertEqual(result['l2tp_sha'], '')
        self.assertEqual(calls, [(REPOS['app'], 'refs/tags/v0.4.0')])

    def test_manual_names_cannot_overwrite_stable_tags(self):
        for name in ['main', 'latest', 'testing', '0.4.0']:
            self.assertTrue(selection('feature', 'main', image_name=name)[0].startswith('testing-'))

    def test_network_errors_are_not_hidden(self):
        def lookup(repo, ref):
            raise subprocess.CalledProcessError(128, ['git'])
        with self.assertRaises(subprocess.CalledProcessError):
            plan('feature', 'branch', resolve_ref=lookup)

    def test_missing_branch_is_distinguished_from_network_failure(self):
        with patch('image_plan.subprocess.run', side_effect=[subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, stdout='')]):
            with self.assertRaises(MissingRef):
                resolve(REPOS['app'], 'missing')
        with patch('image_plan.subprocess.run', side_effect=subprocess.CalledProcessError(128, ['git'])):
            with self.assertRaises(subprocess.CalledProcessError):
                resolve(REPOS['app'], 'branch')

    def test_invalid_inputs_rejected(self):
        cases=[dict(mode='guess', branch='branch'),dict(mode='feature', branch=''),
               dict(mode='feature', branch='a\nb'),dict(mode='feature', branch='refs/heads/a'),
               dict(mode='release', release_tag='v0.4.0-rc1'),
               dict(mode='feature', branch='main', image_name='bad\nname')]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                selection(**case)

    def test_invalid_module_branch_rejected_before_remote_lookup(self):
        with self.assertRaises(ValueError):
            plan('feature', 'main', resolve_ref=lambda repo, ref: 'a' * 40,
                 l2tp_branch='bad\nbranch')

    def test_simple_default_tag(self):
        self.assertEqual(feature_tag('codex/udp-batching'), 'testing-udp-batching')


if __name__ == '__main__':
    unittest.main()
