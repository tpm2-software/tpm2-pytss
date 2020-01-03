TCTIs
=====

TCTIs implement the communication channel between the TSS library and the TPM
itself. There are several TCTIs available which correspond to different use
cases.

You can read more about TCTIs here: https://github.com/tpm2-software/tpm2-tss/wiki/TCTI-loader-library

- ``mssim``

  - Simulator (aka ``tpm_server`` from https://sourceforge.net/projects/ibmswtpm2/)

- ``tabrmd``

  - Userspace resource manager (connects via dbus)

- ``device``

  - Linux kernel /dev/tpm0


To a TCTI with the Enhanced System API you will call
:meth:`tpm2_pytss.tcti.TCTI.load` classmethod passing the name of the TCTI you
want to use (from the above list) as a string to it. You'll get back an instance
of :class:`tpm2_pytss.tcti.TCTI` which will allow you to create context's by
calling the instance of the class.

.. autoclass:: tpm2_pytss.tcti.TCTI
   :members:
   :undoc-members:

.. autoclass:: tpm2_pytss.tcti.TCTIContext
   :members:
   :undoc-members:
