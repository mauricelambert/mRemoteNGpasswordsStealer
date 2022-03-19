from setuptools import setup

setup(
    name="mRemoteNGpasswordsStealer",
    version="1.0.0",
    py_modules=["mRemoteNGpasswordsStealer"],
    install_requires=["PythonToolsKit", "pycryptodome"],
    author="Maurice Lambert",
    author_email="mauricelambert434@gmail.com",
    maintainer="Maurice Lambert",
    maintainer_email="mauricelambert434@gmail.com",
    description="This module steals mRemoteNG passwords.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    include_package_data=True,
    url="https://github.com/mauricelambert/mRemoteNGpasswordsStealer",
    project_urls={
        "Documentation": "https://mauricelambert.github.io/info/python/security/mRemoteNGpasswordsStealer.html",
        "Executable": "https://mauricelambert.github.io/info/python/security/mRemoteNGpasswordsStealer.pyz",
    },
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Natural Language :: English",
        "Topic :: Security",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.9",
        "Operating System :: Microsoft :: Windows",
    ],
    entry_points={
        "console_scripts": [
            "RemotPasswordsStealer = mRemoteNGpasswordsStealer:main"
        ],
    },
    python_requires=">=3.8",
    keywords=[
        "mRemoteNG",
        "Passwords",
        "Decrypt",
        "Steal",
        "Recovery",
        "Security",
    ],
    platforms=["Windows"],
    license="GPL-3.0 License",
)
