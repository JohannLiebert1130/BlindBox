import socket
from time import sleep
import nltk
from diffiehellman.diffiehellman import DiffieHellman
from src.randoms import Randoms
from src.crypto import aes_encrypt, dpi_encrypt, derive_key
from src.blindbox import ADDRESS as BLINDBOX_ADDRESS

nltk.download('punkt')


class Sender:
    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock_to_mb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self._df = DiffieHellman()
        self._df.generate_private_key()
        self._df.generate_public_key()

        self._session_key = None
        self._k = None
        self._k_rand = None

    def connect(self, address):
        """
        The sender(S) in this connect method will attempt to connect
        to the receiver(R) by a regular sock connection. If the
        connection is set up successfully, S and R will execute a key
        exchange protocol then both of them will get a shared secret
        key. After that three keys (a session key Kssl, a key K used in our
        detection protocol, and a key Krand used as a seed) will be derived
        from this secret key. Then, S will try to connect to the middle-
        box by another regular sock connection. If the connection is
        set up successfully, S will execute a secure computation with MB
        so that MB can obtain rules encrypted with key K without knowing K.
        :param address: the receiver's address
        :return:
        """
        try:
            self._sock.connect(address)
        except socket.error as error:
            print(f'Could not connect with the receiver: {error}')
            exit(1)
        except TypeError as error:
            print(f'Type error: {error}')
            exit(1)
        else:
            self._key_exchange(self._df.public_key)
            self._derive_from_secret()
            print('session key', self._session_key)

        try:
            self._sock_to_mb.connect(BLINDBOX_ADDRESS)
        except socket.error as error:
            print(f'Could not connect with blindBox: {error}')
            exit(1)
        except TypeError as error:
            print(f'Type error: {error}')
            exit(1)
        else:
            self._secure_computation_with_mb()

    def _key_exchange(self, public_key):
        """
        After a key exchange using Diffie-Hellman algorithm,
        the sender will agree on a shared secret with the receiver.
        :param public_key: The sender's public key for key exchange.
        :return: None
        """
        key_to_bytes = str(public_key).encode()
        self._sock.sendall(key_to_bytes)

        data = self._sock.recv(20480)
        print(f'data received from the receiver {data}')

        try:
            pk_from_receiver = int(data)
        except ValueError:
            print('Invalid data type!')
        else:
            if self._df.verify_public_key(pk_from_receiver):
                self._df.generate_shared_secret(pk_from_receiver)
                print('I got the shared key:', self._df.shared_key)
            else:
                raise ValueError('Invalid public key from the sender!')

    def _derive_from_secret(self):
        """
        Use the shared key to derive three keys by using a pseudorandom
        generator.
        _session_key: used to encrypt the traffic in the socket.
        _k: used in the detection protocol
        _k_rand: used as a seed for randomness. Since both end-points have the same seed,
                 they will generate the same randomness.
        :return: None
        """
        key_to_bytes = str(self._df.shared_key).encode()

        randoms = Randoms()
        self._session_key = derive_key(key_to_bytes, randoms.random1)
        self._k = derive_key(key_to_bytes, randoms.random2)
        self._k_rand = derive_key(key_to_bytes, randoms.random3)

    def _secure_computation_with_mb(self):
        """
        Sender will use garbled circuits to compute AES(r,k) with the BlindBox while
        the sender do not know the rule and the BlindBox do not know the key k.
        :return:
        """
        pass

    def send(self, data):
        encrypted_data = aes_encrypt(data.encode(), self._session_key)

        self._sock_to_mb.sendall(encrypted_data)
        sleep(0.4)

        tokens = nltk.word_tokenize(data)
        encrypted_tokens = b''
        for token in tokens:
            encrypted_tokens += dpi_encrypt(token.encode(), self._session_key)
            encrypted_tokens += b' '

        self._sock_to_mb.sendall(encrypted_tokens)


if __name__ == '__main__':
    sender = Sender()
    sender.connect(('127.0.0.1', 7777))
    sender.send('a secret message')
