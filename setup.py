from setuptools import setup, find_packages

setup(
    name="mirage",
    version="2.2.0",
    description="Mirage — Active Deception Platform by TrinTech Digital Defense",
    author="TrinTech Digital Defense",
    author_email="trintechdigitaldefense@gmail.com",
    url="https://trintechdigitaldefense.github.io",
    packages=find_packages(include=["mirage", "mirage.*"]),
    install_requires=[
        "psutil>=5.9.0",
        "requests>=2.28.0",
        "rich>=13.0.0",
        "paramiko>=3.0.0",
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "mirage=mirage.cli:main",
        ]
    },
)
