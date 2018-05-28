import socket

ADDRESS = ('127.0.0.1', 5050)


class BlindBox:
    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(ADDRESS)
        self._sock.listen(10)

    def detect(self):
        while True:
            # Wait for a connection
            connection, address = self._sock.accept()

            encrypted_data = connection.recv(1024)
            print(encrypted_data)

            encrypted_tokens = connection.recv(20480)
            print(encrypted_tokens)

            # self.check_tokens(encrypted_tokens)
            # if check tokens do not raise any error or stop the connection,
            # the codes will continue executing.

            # self.forward_traffic(encrypted_data)

    def check_tokens(self, encrypted_tokens):
        """
        this method will search for matchings between the encrypted rules
        and the encrypted tokens. If there is a match, one can choose the same actions
        as in a regular (unencrypted IDS) such as drop the packet,
        stop the connection, or notify an administrator.
        :param encrypted_tokens:
        :return:
        """
        # for encrypted_token in encrypted_tokens:
        #     if encrypted_token in self.rule_tree:
        #         # do something
        #         pass
        pass


if __name__ == '__main__':
    bd = BlindBox()
    bd.detect()


