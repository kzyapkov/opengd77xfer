from setuptools import setup

setup(
    name="opengd77py",
    description="Python code to talk to OpenGD77 radios",
    packages=['opengd77'],
    install_requires=['pyserial'],
    entry_points={
        "console_scripts": [
            "gd77xfer = opengd77.xfer:main",
        ],
    },
)