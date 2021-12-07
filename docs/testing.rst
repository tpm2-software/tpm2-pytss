Testing
-------

You need to have ``tpm_server`` or ``swtpm``  installed in your path to run the tests.

Download the latest version of tpm_server from https://sourceforge.net/projects/ibmswtpm2/files/
or swtpm from https://github.com/stefanberger/swtpm and put it somewhere in your ``$PATH``.

.. code-block:: console

    $ pip install -e .[dev]
    $ pytest -n$(nproc) -v test
