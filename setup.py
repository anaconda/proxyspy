from setuptools import setup

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="proxy-tester",
    version="0.1.0",
    author="Anaconda, Inc.",
    author_email="conda@anaconda.com",
    description="A debugging proxy that can log or intercept HTTPS requests",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/anaconda/proxy-tester",
    py_modules=["proxy_tester"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography",
    ],
    extras_require={
        "test": ["pytest", "requests", "psutil"],
    },
    entry_points={
        "console_scripts": [
            "proxy-tester=proxy_tester:main",
        ],
    },
)
