import os
import socket
from time import sleep

from diffiehellman.diffiehellman import DiffieHellman

from src.utils import tokenize
from src.crypto import aes_decrypt, aes_encrypt, dpi_encrypt
from src.blindbox import ADDRESS as BLINDBOX_ADDRESS


class Sender:
    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock_to_mb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self._df = DiffieHellman(key_length=2048)
        self._df.generate_private_key()
        self._df.generate_public_key()

        self._shared_secret = None
        self._session_key = os.urandom(32)
        self._k = None
        self._k_rand = None

    def connect(self, address):
        try:
            self._sock.connect(address)
        except socket.error as error:
            print(f'Could not connect with the receiver: {error}')
        except TypeError as error:
            print(f'Type error: {error}')
        else:
            self._key_exchange(self._df.public_key)

        try:
            self._sock_to_mb.connect(BLINDBOX_ADDRESS)
        except socket.error as error:
            print(f'Could not connect with blindBox: {error}')
        except TypeError as error:
            print(f'Type error: {error}')
        else:
            self._secure_computation_with_mb()

    def _key_exchange(self, public_key):
        """
        After a key exchange using Diffie-Hellman algorithm,
        the sender will agree on a shared secret with the receiver.
        :param public_key: The sender's public key for key exchange.
        :return: None
        """
        pass

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
        self._session_key = None
        self._k = None
        self._k_rand = None

    def _secure_computation_with_mb(self):
        """
        Sender will use garbled circuits to compute AES(r,k) with the BlindBox while
        the sender do not know the rule and the BlindBox do not know the key k.
        :return:
        """
        pass

    def send(self, data):
        encrypted_data = aes_encrypt(data, self._session_key)

        self._sock_to_mb.sendall(encrypted_data)
        sleep(0.4)

        tokens = tokenize(data)
        encrypted_tokens = b''
        for token in tokens:
            encrypted_tokens += dpi_encrypt(token, self._session_key)

        self._sock_to_mb.sendall(encrypted_tokens)


if __name__ == '__main__':
    sender = Sender()
    sender.connect(('127.0.0.1', 7777))
    sender.send(b'a secret message')


