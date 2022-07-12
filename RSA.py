# Reference
# https://ossa2019.stars.ne.jp/blog/other/rsa.html
# https://qiita.com/QUANON/items/e7b181dd08f2f0b4fdbe
import random
import sympy

class RSA(object):
    """RSA cipher."""
    def __init__(self, sender=False):
        if sender:
            self.sender = True
        else:
            self.sender = False
    
    def __repr__(self):
        if self.sender:
            return 'Sender.'
        else:
            return 'Reciever.'
    
    def gcd(self, a, b):
        """Return the greatest common divisor of a and b."""
        if b == 0:
            return a
        return self.gcd(b, a % b)
    
    def extgcd(self, a, b):
        """Return a pair (x, y) satisfying ax+by=gcd(a,b)."""
        if b == 0:
            return 1, 0
        s, t = self.extgcd(b, a % b)
        return t, s - (a // b) * t
    
    def lcm(self, a, b):
        """Return the least common multiple of a and b."""
        return int(a * b / self.gcd(a, b))

    def mod_inverse(self, a, m):
        """Return the inverse of a modulo m."""
        if self.gcd(a, m) != 1:
            return None # There is no inverse if gcd(a, m)>1.
        x, y = self.extgcd(a, m)
        if x < 0:
            while x < 0:
                x = x + m # Add m so that x>0.
        return x
    
    def is_sender(self):
        return self.sender
    
    def is_reciever(self):
        return not self.sender

    def generate_primes(self):
        """Generate two distict primes p, q (which are greater than 2 ** b)."""
        b = 7 # Changeable Parameter.
        while True:
            p = sympy.randprime(2**b, 2**(b+1))
            q = sympy.randprime(2**b, 2**(b+1))
            if p != q:
                return (p, q)

    def generate_keys(self):
        """Generate a public key (e, N) and a private key (d, N)."""
        p, q = self.generate_primes()
        N = p * q
        L = self.lcm(p - 1, q - 1)
        while True:
            i = random.randint(2, L)
            if self.gcd(i, L) == 1:
                e = i
                break
        d = self.mod_inverse(e, L)
        return (e, N), (d, N)

    def encrypt(self, plain_text, public_key):
        """Encrypt a text by a public key."""
        e, N = public_key
        plain_integers = [ord(char) for char in plain_text]
        encrypted_integers = [(i ** e) % N for i in plain_integers]
        encrypted_text = ''.join(chr(i) for i in encrypted_integers)
        return encrypted_text
    
    def decrypt(self, encrypted_text, private_key):
        """Decrypt a encrypted text by a private key."""
        d, N = private_key
        encrypted_integers = [ord(char) for char in encrypted_text]
        decrypted_integers = [(i ** d) % N for i in encrypted_integers]
        decrypted_text = ''.join(chr(i) for i in decrypted_integers)
        return decrypted_text

if __name__ == '__main__':

    # Send a message with RSA encryption.
    Bob = RSA(sender=False)
    PUBLIC_KEY, PRIVATE_KEY = Bob.generate_keys()
    print(f"""\
Public and private key have been generated:
PUBLIC KEY : {PUBLIC_KEY}
PRIVATE KEY : {PRIVATE_KEY}\
""")

    Alice = RSA(sender=True)
    plain_text = input('Enter text:')
    encrypted_text = Alice.encrypt(plain_text, PUBLIC_KEY)
    print(f'Encrypted Text:{encrypted_text.encode("utf-8", "replace").decode("utf-8")}')

    decrypted_text = Bob.decrypt(encrypted_text, PRIVATE_KEY)
    print(f'Decrypted Text:{decrypted_text}')

