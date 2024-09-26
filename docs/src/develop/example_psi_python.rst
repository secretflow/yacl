Example: Bind PSI to Python
===========================

This is an example of how to use Yacl's ECC api and link to build up a `PSI (Private Set Intersection) <https://en.wikipedia.org/wiki/Private_set_intersection>`_ protocol, and provide a python language binding using `pybind11 <https://github.com/pybind/pybind11>`_. The code of this example is avaliable on `Github <https://github.com/secretflow/yacl/tree/main/examples/psi/python>`_.

.. warning::
   This example is merely designed for demonstration only, please do not use this example in production.

Step 1: Implement
^^^^^^^^^^^^^^^^^

.. literalinclude:: ../../../examples/psi/python/ecdh_psi_pybind.h
  :language: cpp

.. literalinclude:: ../../../examples/psi/python/ecdh_psi_pybind.cc
  :language: cpp

.. literalinclude:: ../../../examples/psi/python/ecdh_psi.py
  :language: python

Step 2: Build and Test
^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: ../../../examples/psi/python/ecdh_psi_test.py
  :language: python
