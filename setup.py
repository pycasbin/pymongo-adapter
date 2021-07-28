from setuptools import setup, find_packages, __version__
from os import path

desc_file = "README.md"

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(desc_file, "r") as fh:
    long_description = fh.read()

# get the dependencies and installs
with open(path.join(here, "requirements.txt"), encoding="utf-8") as f:
    all_reqs = f.read().split("\n")

install_requires = [x.strip() for x in all_reqs if "git+" not in x]


setup(
    name="casbin_pymongo_adapter",
    author="TechLee,Xhy-5000,AmosChenYQ",
    author_email="techlee@qq.com,amoschenyq@foxmail.com",
    description="PyMongo Adapter for PyCasbin",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pycasbin/pymongo-adapter",
    keywords=[
        "casbin",
        "pymongo",
        "casbin-adapter",
        "rbac",
        "access control",
        "abac",
        "acl",
        "permission",
    ],
    packages=find_packages(),
    install_requires=install_requires,
    python_requires=">=3.6",
    license="Apache 2.0",
    classifiers=[
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    data_files=[desc_file],
)
