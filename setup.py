from setuptools import setup, find_packages

setup(
    name="secure-iam-lint",
    version="0.1.0",
    author="[rivassec]",
    description="A lightweight linter for AWS IAM policies",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/secure-iam-lint",  # update when published
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "argparse",  # usually included in stdlib for Python 3.2+
    ],
    entry_points={
        "console_scripts": [
            "iam-lint=iamlint.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Utilities",
        "Development Status :: 3 - Alpha",
    ],
    python_requires=">=3.7",
)
