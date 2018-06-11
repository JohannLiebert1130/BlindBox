import os


class Randoms:
    def __init__(self):
        self.random1 = None
        self.random2 = None
        self.random3 = None

        self.read_randoms()

    @staticmethod
    def save_randoms():
        with open('randoms', 'wb') as file:
            file.write(os.urandom(16))
            file.write(os.urandom(16))
            file.write(os.urandom(16))

    def read_randoms(self):
        with open('randoms', 'rb') as file:
            self.random1 = file.readline()
            self.random2 = file.readline()
            self.random3 = file.readline()


if __name__ == '__main__':
    Randoms.save_randoms()





