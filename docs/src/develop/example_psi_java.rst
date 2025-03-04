Example: Bind PSI to Java
=========================

This is an example of how to use Yacl's ECC api and link to build up a `PSI (Private Set Intersection) <https://en.wikipedia.org/wiki/Private_set_intersection>`_ protocol, and provide a java language binding using JNI. The code of this example is avaliable on `Github <https://github.com/secretflow/yacl/tree/main/examples/psi/java>`_.

.. warning::
   This example is merely designed for demonstration only, please do not use this example in production.

Step 1: Implement
^^^^^^^^^^^^^^^^^

.. literalinclude:: ../../../examples/psi/java/ecdh_psi_jni.cc
  :language: cpp

.. literalinclude:: ../../../examples/psi/java/EcdhPsi.java
  :language: java

Step 2: Build and Test
^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: ../../../examples/psi/java/EcdhPsiTest.java
  :language: java
