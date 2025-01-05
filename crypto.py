from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as apadding
import base64


class Crypto_AES(object):
    def __init__(self, password=b'') -> None:
        _kdf = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=48,
            otherinfo=None
        )
        _keyiv = _kdf.derive(password)
        self.key = _keyiv[:32]
        self.iv = _keyiv[32:]
        self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))

    def encrypt(self, plainbytes: bytes) -> str:
        _encryptor = self.cipher.encryptor()
        _padder = padding.PKCS7(algorithms.AES.block_size).padder()
        _padded_data = _padder.update(plainbytes) + _padder.finalize()
        _cipherbytes = _encryptor.update(_padded_data) + _encryptor.finalize()
        return base64.urlsafe_b64encode(_cipherbytes).decode()

    def decrypt(self, cipherb64: str) -> bytes:
        _decryptor = self.cipher.decryptor()
        _cipherbytes = base64.urlsafe_b64decode(cipherb64)
        _padded_plainbytes = _decryptor.update(_cipherbytes) + _decryptor.finalize()
        _unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return _unpadder.update(_padded_plainbytes) + _unpadder.finalize()


class Crypto_RSA(object):
    def __init__(self) -> None:
        self.private_key = None
        self.public_key = None
        self.public_pem = None

    def generate(self, size=2048):
        if size < 512:
            print('[W] Key size is too small, using 512 instead.')
            size = 512
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=size)
        self.public_key = self.private_key.public_key()
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def encrypt(self, plainbytes: bytes) -> str:
        _cipherbytes = self.public_key.encrypt(
            plainbytes,
            apadding.OAEP(
                mgf=apadding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.urlsafe_b64encode(_cipherbytes).decode()

    def decrypt(self, cipherb64: str) -> bytes:
        _cipherbytes = base64.urlsafe_b64decode(cipherb64)
        return self.private_key.decrypt(
            _cipherbytes,
            apadding.OAEP(
                mgf=apadding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def load_public_key(self, pem: str) -> None:
        self.public_key = serialization.load_pem_public_key(pem.encode())
        self.public_pem = pem
