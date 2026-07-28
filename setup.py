from setuptools import setup, find_packages

setup(
    name="mirage",
    version="1.0.0",
    description="Mirage Deception Grid — TrinTech Digital Defense",
    author="Jason Junior Ramdharry",
    author_email="trintechdigitaldefense@gmail.com",
    url="https://trintechdigitaldefense.github.io",
    packages=find_packages(),
    install_requires=["scapy>=2.4.5"],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "mirage=mirage.__main__:main"
        ]
    },
)
