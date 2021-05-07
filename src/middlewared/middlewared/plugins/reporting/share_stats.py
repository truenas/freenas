# -*- coding=utf-8 -*-
class ShareStats:
    def __init__(self, middleware):
        self.middleware = middleware
        self.i = 0
        self.stats = {}

    def get(self):
        if self.i % 30 == 0:
            for (name, service, plugin) in [
                ("iscsi", "iscsitarget", "iscsi.global"),
                ("nfs", "nfs", "nfs"),
                ("smb", "cifs", "smb")
            ]:
                client_count = 0
                try:
                    if self.middleware.call_sync("service.started", service):
                        client_count = self.middleware.call_sync(f"{plugin}.client_count")
                except Exception:
                    self.middleware.logger.trace("Error retrieving %r share stat", name, exc_info=True)

                self.stats[name] = {
                    "client_count": client_count,
                }

        self.i += 1

        return self.stats
