"""
rename this to test_assumptions.py when the old assumptions system is deleted
"""
from sympy.abc import x, y
from sympy.assumptions.assume import global_assumptions, Predicate
from sympy.assumptions.ask import _extract_facts, Q
from sympy.core import symbols
from sympy.core.power import Pow
from sympy.core.singleton import S
from sympy.core.symbol import Symbol
from sympy.logic.boolalg import Or
from sympy.printing import pretty


def test_equal():
    """Test for equality"""
    assert Q.positive(x) == Q.positive(x)
    assert Q.positive(x) != ~Q.positive(x)
    assert ~Q.positive(x) == ~Q.positive(x)


def test_pretty():
    assert pretty(Q.positive(x)) == "Q.positive(x)"
    assert pretty(
        set([Q.positive, Q.integer])) == "set([Q.integer, Q.positive])"


def test_extract_facts():
    a, b = symbols('a b', cls=Predicate)
    assert _extract_facts(a(x), x) == a
    assert _extract_facts(a(x), y) is None
    assert _extract_facts(~a(x), x) == ~a
    assert _extract_facts(~a(x), y) is None
    assert _extract_facts(a(x) | b(x), x) == a | b
    assert _extract_facts(a(x) | ~b(x), x) == a | ~b
    assert _extract_facts(a(x) & b(y), x) == a
    assert _extract_facts(a(x) & b(y), y) == b
    assert _extract_facts(a(x) | b(y), x) == None
    assert _extract_facts(~(a(x) | b(y)), x) == ~a


def test_global():
    """Test for global assumptions"""
    global_assumptions.add(Q.is_true(x > 0))
    assert Q.is_true(x > 0) in global_assumptions
    global_assumptions.remove(Q.is_true(x > 0))
    assert not Q.is_true(x > 0) in global_assumptions
    # same with multiple of assumptions
    global_assumptions.add(Q.is_true(x > 0), Q.is_true(y > 0))
    assert Q.is_true(x > 0) in global_assumptions
    assert Q.is_true(y > 0) in global_assumptions
    global_assumptions.clear()
    assert not Q.is_true(x > 0) in global_assumptions
    assert not Q.is_true(y > 0) in global_assumptions


def test_composite_predicates():
    pred = Q.integer | ~Q.positive
    assert type(pred(x)) is Or
    assert pred(x) == Q.integer(x) | ~Q.positive(x)


def test_sqrt_rational():
    """
    (sympy)pzrq@Peters-Mini-2:~/Projects/sympy$ ipython
    Python 2.7.6 (default, Sep  9 2014, 15:04:36)
    Type "copyright", "credits" or "license" for more information.

    IPython 2.3.1 -- An enhanced Interactive Python.
    ?         -> Introduction and overview of IPython's features.
    %quickref -> Quick reference.
    help      -> Python's own help system.
    object?   -> Details about 'object', use 'object??' for extra details.

    In [1]: import os

    In [2]: os.environ['SYMPY_USE_CACHE'] = 'no'

    In [3]: import sympy

    In [4]: sympy.test('sympy/assumptions/tests/test_assumptions_2')

    ... <lots of output>

    RuntimeError: maximum recursion depth exceeded in __instancecheck__

    =============================== tests finished: 5 passed, 1 exceptions, in 0.03 seconds ===============================
    DO *NOT* COMMIT!
    Out[4]: False
    """
    expr = Pow(Symbol('x'), S.Half)
    assert expr.is_rational is None
