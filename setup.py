from setuptools import setup, find_packages

setup(
    name="csb_cipher_lib",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A Python library implementing the Shadowbourne (CSB) cipher and key management.",
    packages=find_packages(),
    install_requires=[
        "argon2-cffi",  # required for key derivation
    ],
    python_requires=">=3.6",  # Require Python 3.6 or newer
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
