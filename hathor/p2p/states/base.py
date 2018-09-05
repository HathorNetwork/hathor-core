
class BaseState(object):
    def send_message(self, cmd, payload=None):
        self.protocol.send_message(cmd, payload)

    def on_enter(self):
        pass

    def on_exit(self):
        pass
