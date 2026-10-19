import unittest
from image_plan import REPOS, feature_tag, plan


class ImagePlanTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

    def resolve(self, repo, ref):
        self.calls.append((repo, ref))
        return {REPOS['app']: 'a', REPOS['l2tp']: 'b', REPOS['ipsec']: 'c'}[repo] * 40

    def test_app_feature_uses_exact_commit_and_main_libraries(self):
        result = plan('push', {'ref': 'refs/heads/new-auth', 'after': 'd' * 40}, self.resolve)
        self.assertEqual(result, dict(tag='testing-new-auth', app_sha='d' * 40, l2tp_sha='b' * 40, ipsec_sha='c' * 40))
        self.assertEqual(self.calls, [(REPOS['l2tp'], 'main'), (REPOS['ipsec'], 'main')])

    def test_main_uses_latest_main_in_all_repos(self):
        result = plan('push', {'ref': 'refs/heads/main', 'after': 'd' * 40}, self.resolve)
        self.assertEqual(result['tag'], 'testing')
        self.assertEqual(result['app_sha'], 'a' * 40)
        self.assertEqual(self.calls, [(repo, 'main') for repo in REPOS.values()])

    def test_each_library_feature_keeps_its_exact_commit(self):
        for source in ('l2tp', 'ipsec'):
            with self.subTest(source=source):
                result = plan('repository_dispatch', {'client_payload': {'repository': REPOS[source], 'branch': 'new-auth', 'sha': 'd' * 40}}, self.resolve)
                self.assertEqual(result['tag'], 'testing-new-auth')
                self.assertEqual(result[source + '_sha'], 'd' * 40)
                self.assertEqual(result['app_sha'], 'a' * 40)

    def test_library_main_is_shared_testing(self):
        result = plan('repository_dispatch', {'client_payload': {'repository': REPOS['ipsec'], 'branch': 'main', 'sha': 'd' * 40}}, self.resolve)
        self.assertEqual(result['tag'], 'testing')
        self.assertEqual(result['ipsec_sha'], 'c' * 40)

    def test_manual_combined_feature_resolves_all_explicit_branches(self):
        result = plan('workflow_dispatch', {'inputs': {'feature': 'new-auth', 'app_ref': 'auth-ui', 'l2tp_ref': 'auth-ppp', 'ipsec_ref': 'auth-ike'}}, self.resolve)
        self.assertEqual(result['tag'], 'testing-new-auth')
        self.assertEqual(self.calls, [(REPOS['app'], 'auth-ui'), (REPOS['l2tp'], 'auth-ppp'), (REPOS['ipsec'], 'auth-ike')])

    def test_release_uses_tag_and_leaves_pinned_modules(self):
        result = plan('release', {'release': {'tag_name': 'v0.4.0'}}, self.resolve)
        self.assertEqual(result, dict(tag='0.4.0', app_sha='a' * 40, l2tp_sha='', ipsec_sha=''))
        self.assertEqual(self.calls, [(REPOS['app'], 'refs/tags/v0.4.0')])

    def test_normalized_feature_names_cannot_collide(self):
        names = ['feature/auth', 'feature-auth', 'Feature-auth', 'feature_auth', 'a' * 200]
        tags = [feature_tag(name) for name in names]
        self.assertEqual(len(set(tags)), len(tags))
        for tag in tags:
            self.assertLessEqual(len(tag), 128)
            self.assertRegex(tag, r'^testing-[a-z0-9_.-]+$')
            self.assertNotEqual(tag, 'testing')

    def test_reject_invalid_events_and_payloads(self):
        cases = [
            ('push', {'ref': 'refs/tags/v0.4.0', 'after': 'a' * 40}),
            ('push', {'ref': 'refs/heads/auth', 'after': 'a' * 40, 'deleted': True}),
            ('push', {'ref': 'refs/heads/auth', 'after': 'invalid'}),
            ('repository_dispatch', {'client_payload': {'repository': 'other/repo', 'branch': 'main', 'sha': 'a' * 40}}),
            ('release', {'release': {'tag_name': 'v0.4.0-rc1'}}),
            ('workflow_dispatch', {'inputs': {'feature': ''}}),
        ]
        for event, payload in cases:
            with self.subTest(event=event, payload=payload), self.assertRaises(ValueError):
                plan(event, payload, self.resolve)


if __name__ == '__main__':
    unittest.main()
