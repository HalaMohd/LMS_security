from django.test import TestCase

# Create your tests here.
# CI pipeline test comment

class DummyFailTest(TestCase):
    def test_fail_on_purpose(self):
        self.assertEqual(1, 2)