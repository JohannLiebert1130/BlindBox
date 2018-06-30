import socket
import subprocess
from src.constants import OBLIVC_AES_PATH

ADDRESS = ('127.0.0.1', 6666)
ADDRESS2 = ('127.0.0.1', 8785)

rules = ["attack", "violence", "fuck", "shit", "damn"]


class BlindBox:
    def __init__(self):
        self._sock_for_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock_for_s.bind(ADDRESS)
        self._sock_for_s.listen(10)

        self._sock_for_r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock_for_r.bind(ADDRESS2)
        self._sock_for_r.listen(10)

    def detect(self):
        while True:
            # Wait for a connection
            connection, address = self._sock_for_s.accept()
            connection2, address2 = self._sock_for_r.accept()

            self.rule_preparation(connection, connection2)

            encrypted_data = connection.recv(20480)
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

    def rule_preparation(self, connection,  connection2):
        key_numbers = len(rules)
        #
        connection.sendall(str(key_numbers).encode())
        connection2.sendall(str(key_numbers).encode())

        for rule in rules:
            output1 = subprocess.getoutput(OBLIVC_AES_PATH + "/a.out 1235 localhost " + rule)
            output2 = subprocess.getoutput(OBLIVC_AES_PATH + "/a.out 5321 localhost " + rule)
            while output1 == "TCP connect failed":
                output1 = subprocess.getoutput(OBLIVC_AES_PATH + "/a.out 1235 localhost " + rule)
            while output2 == "TCP connect failed":
                output2 = subprocess.getoutput(OBLIVC_AES_PATH + "/a.out 1235 localhost " + rule)
            if output1[108:] != output2[108:]:
                print('You are in danger!')
                exit(1)


if __name__ == '__main__':
    bd = BlindBox()
    bd.detect()
