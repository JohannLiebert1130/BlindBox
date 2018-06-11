import socket

from diffiehellman.diffiehellman import DiffieHellman

from src.constants import RANDOM_1, RANDOM_2, RANDOM_3
from src.crypto import aes_decrypt, aes_encrypt, dpi_encrypt, derive_key
ADDRESS = ('127.0.0.1', 7777)


class Sender:
    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock_to_mb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self._sock.bind(ADDRESS)
        self._sock.listen(10)

        self._df = DiffieHellman()
        self._df.generate_private_key()
        self._df.generate_public_key()

        self._session_key = None
        self._k = None
        self._k_rand = None

    def connection_setup(self):
        while True:
            # Wait for a connection
            connection, address = self._sock.accept()
            self._key_exchange(connection, self._df.public_key)
            print('My shared key:', self._df.shared_key)
            self._derive_from_secret()
            print('session key', self._session_key)

    def _key_exchange(self, connection, public_key):
        """
        After a key exchange using Diffie-Hellman algorithm,
        the sender will agree on a shared secret with the receiver.
        :param public_key: The sender's public key for key exchange.
        :return: None
        """
        data = connection.recv(20480)
        print(f'data received from the sender: {data}')

        try:
            pk_from_sender = int(data)
        except ValueError:
            print('Invalid data type!')
        else:
            if self._df.verify_public_key(pk_from_sender):
                self._df.generate_shared_secret(pk_from_sender)
                print('I got the shared key:', self._df.shared_key)
                connection.sendall(str(public_key).encode())
            else:
                raise ValueError('Invalid public key from the sender!')

    def _derive_from_secret(self):
        """
        Use the shared secret to derive three keys by using a pseudorandom
        generator.
        _session_key: used to encrypt the traffic in the socket.
        _k: used in our detection protocol
        _k_rand: used as a seed for randomness. Since both end-points have the same seed,
                 they will generate the same randomness.
        :return: None
        """
        key_to_bytes = str(self._df.shared_key).encode()
        self._session_key = derive_key(key_to_bytes, RANDOM_1)
        self._k = derive_key(key_to_bytes, RANDOM_2)
        self._k_rand = derive_key(key_to_bytes, RANDOM_3)

    def _secure_computation_with_mb(self):
        """
        Sender will use garbled circuits to compute AES(r,k) with the BlindBox while
        the sender do not know the rule and the BlindBox do not know the key k.
        :return:
        """
        pass

    def receive(self):
        encrypted_traffic = self._sock_to_mb.recv(20480)
        encrypted_tokens = self._sock_to_mb.recv(20480)

        traffic = aes_decrypt(encrypted_traffic)

        self.check_tokens(traffic, encrypted_tokens)

    def check_tokens(self, traffic, encrypted_tokens):
        pass


if __name__ == '__main__':
    sender = Sender()
    sender.connection_setup()


