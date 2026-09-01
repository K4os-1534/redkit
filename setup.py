"""
RedKit setup.py — makes RedKit installable as a package with a 'redkit' console entry point.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="redkit",
    version="1.0.0",
    author="K4os",
    description="Modular menu-driven automated red teaming tool targeting web applications.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "redkit=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Environment :: Console",
    ],
    include_package_data=True,
    package_data={
        "": ["wordlists/*.txt", "templates/*.j2", "config.yaml"],
    },
)
