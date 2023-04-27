from setuptools import setup, find_packages
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(here, "README.md"), encoding="utf-8") as fh:
    long_description = "\n" + fh.read()

VERSION = '0.0.16'
DESCRIPTION = 'AES Stream Cipher with CFB and OpenPGP Modes'
LONG_DESCRIPTION = 'A package that allows you to build encrypt variable sized files using AES as a stream cipher with CFB and OpenPGP modes'

# Setting up
setup(
    name="Sandra",
    version=VERSION,
    author="George Assaad",
    author_email="<lopgogo@gmail.com>",
    url='https://github.com/lopgogo/Sandra',
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=long_description,
    packages=find_packages(exclude=['tests']),
    install_requires=['pycryptodome', 'pandas'],
    keywords=['python', 'encryption', 'decryption', 'cipher', 'cryptography'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)