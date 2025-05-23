import routeros_api

class MikrotikAPI:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.connection = None

    def connect(self):
        self.connection = routeros_api.RouterOsApiPool(
            self.host,
            username=self.username,
            password=self.password,
            plaintext_login=True
        )

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()

    def remove_mangle_rules(self, comment):
        api = self.connection.get_api().get_resource('/ip/firewall/mangle')
        rules = api.get()
        for rule in rules:
            if 'comment' in rule and rule['comment'] == comment:
                api.remove(rule['id'])

    def add_mangle_rule(self, src_address, in_interface, comment):
        api = self.connection.get_api().get_resource('/ip/firewall/mangle')
        rule = {
            "chain": "prerouting",
            "src-address": src_address,
            "in-interface": in_interface,
            "action": "mark-connection",
            "new-connection-mark": "pppoe-mangle",
            "passthrough": "yes",
            "comment": comment
        }
        api.add(rule)
