PyMongo Adapter for PyCasbin
====

[![Build Status](https://www.travis-ci.org/pycasbin/pymongo-adapter.svg?branch=master)](https://www.travis-ci.org/pycasbin/pymongo-adapter)
[![Coverage Status](https://coveralls.io/repos/github/pycasbin/pymongo-adapter/badge.svg)](https://coveralls.io/github/pycasbin/pymongo-adapter)
[![Version](https://img.shields.io/pypi/v/casbin_pymongo_adapter.svg)](https://pypi.org/project/casbin_pymongo_adapter/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/casbin_pymongo_adapter.svg)](https://pypi.org/project/casbin_pymongo_adapter/)
[![Pyversions](https://img.shields.io/pypi/pyversions/casbin_pymongo_adapter.svg)](https://pypi.org/project/casbin_pymongo_adapter/)
[![Download](https://img.shields.io/pypi/dm/casbin_pymongo_adapter.svg)](https://pypi.org/project/casbin_pymongo_adapter/)
[![License](https://img.shields.io/pypi/l/casbin_pymongo_adapter.svg)](https://pypi.org/project/casbin_pymongo_adapter/)

PyMongo Adapter is the [PyMongo](https://pypi.org/project/pymongo/) adapter for [PyCasbin](https://github.com/casbin/pycasbin). With this library, Casbin can load policy from MongoDB or save policy to it.

## Installation

```
pip install casbin_pymongo_adapter
```

## Simple Example

```python
import casbin_pymongo_adapter
import casbin

adapter = casbin_pymongo_adapter.Adapter('mongodb://localhost:27017/', "dbname")

e = casbin.Enforcer('path/to/model.conf', adapter, True)

sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act):
    # permit alice to read data1casbin_sqlalchemy_adapter
    pass
else:
    # deny the request, show an error
    pass
```


### Getting Help

- [PyCasbin](https://github.com/casbin/pycasbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).
