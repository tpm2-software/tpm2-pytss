Release Process
===============

Information on the release process and guidelines for maintainers.

Milestones
-----------

All releases should have a milestone used to track the release. If the release version is not known, as covered in `version string`_,
then an "x" may be used for the unknown number, or the generic term "next" may be used. The description field of the milestone will be used to record
the CHANGELOG for that release. See `changelog update`_ for details.

Version Numbers
---------------

Our releases will follow the semantic versioning scheme.
You can find a thorough description of this scheme here: `<http://semver.org/>`_
In short, this scheme has 3 parts to the version number: A.B.C

- A is the 'major' version, incremented when an API incompatible change is made
- B is the 'minor' version, incremented when an API compatible change is made
- C is the 'micro' version, incremented for bug fix releases

Please refer to the `Semantic Versioning <http://semver.org/>`_ website for the authoritative description.

.. _version string:

Version String
^^^^^^^^^^^^^^

The version string is set by setup tools using `use_scm_version <https://pypi.org/project/setuptools-scm/>`_. Thus one must get a source built
package from pypi or use the git repository.

.. note::

    The auto-generated zip and tarballs from GitHub WILL NOT WORK.

The version string must be in the form ``A.B.C`` where ``A``, ``B`` and ``C`` are integers representing the major, minor and micro components of the
version number.

Release Candidates
^^^^^^^^^^^^^^^^^^

In the run up to a release the maintainers may create tags to identify progress toward the release.
In these cases we will append a string to the release number to indicate progress using the abbreviation ``rc`` for "release candidate".
This string will take the form of ``-rcX``.
We append an incremental digit ``X`` in case more than one release candidate is necessary to communicate progress as development moves forward.

.. _changelog update:

CHANGELOG Update
----------------

Before tagging the repository with the release version, the maintainer MUST update the CHANGELOG file with the contents from the description field
from the corresponding release milestone and update any missing version string details in the CHANGELOG and milestone entry.

Git Tags
--------

When a release is made a tag is created in the git repo identifying the release by the `version string`_.
The tag should be pushed to upstream git repo as the last step in the release process.

Signed tags
^^^^^^^^^^^

Git supports GPG signed tags and for releases after the `1.1.0` release will have tags signed by a maintainer.
For details on how to sign and verify git tags see `<https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work>`_.

Hosting Releases on PyPI
------------------------

The CI system has been automated to automatically create a release on any signed tag. This release will be packaged and uploaded
to PyPi `<https://pypi.org/project/tpm2-pytss>`_.


Hosting Documents on ReadTheDocs
--------------------------------

For each tag, a ReadTheDocs (RTD) build must be conducted on LGTM manually after the release has been conducted. Maintainers should
have access to the RTD page where they can select the reference and "activate" it in the release list. A fly-out menu contains the
various versions and latest will point to master. See `<https://docs.readthedocs.io/en/stable/versions.html>`_ for more details.

.. note::

    Release Candidate Tags should be removed to prevent cluttering of the available document versioning.

Signing Keys
------------

The GPG keys used to sign a release tag and the associated tarball must be the same.
Additionally they must:
* belong to a project maintainer
* be discoverable using a public GPG key server
* be associated with the maintainers github account `<https://help.github.com/articles/adding-a-new-gpg-key-to-your-github-account/>`_

Announcements
-------------

Release candidates and proper releases should be announced on the 01.org TPM2 mailing list: `<https://lists.01.org/postorius/lists/tpm2.lists.01.org/>`_.
This announcement should be accompanied by a link to the release page on Github as well as a link to the CHANGELOG.md accompanying the release.

