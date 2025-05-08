from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="xploit",
    version="0.1.0",
    author="Security Researcher",
    author_email="researcher@example.com",
    description="A tool for targeted database enumeration via parameter injection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/xploit",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "xploit=xploit.main:main",
        ],
    },
)