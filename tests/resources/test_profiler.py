from hathor.resources import ProfilerResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import StubSite, _BaseResourceTest
from pathlib import Path


class ProfilerTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(ProfilerResource(self.manager))

    @inlineCallbacks
    def test_post(self):
        # Options
        yield self.web.options("profiler")

        dump_file = Path('profiles/profile001.prof')
        self.assertFalse(dump_file.is_file())

        # Start profiler
        response_start = yield self.web.post("profiler", {'start': True})
        data_start = response_start.json_value()
        self.assertTrue(data_start['success'])

        # Stop profiler
        response_stop = yield self.web.post("profiler", {'stop': True})
        data_stop = response_stop.json_value()
        self.assertTrue(data_stop['success'])

        # Validate dump file created
        self.assertTrue(dump_file.is_file())

        # Success false
        response_error = yield self.web.post("profiler")
        data_error = response_error.json_value()
        self.assertFalse(data_error['success'])
