"""Compatibility shim: the package was renamed to ``tracevoryx`` in 0.3.0.

``import trustweave`` keeps working; new code should import ``tracevoryx``.
"""
import importlib as _importlib

_m = _importlib.import_module("tracevoryx.core.policy")
globals().update({n: getattr(_m, n) for n in dir(_m) if not n.startswith("__")})
