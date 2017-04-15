============
Contributing
============
Report a Bug or Make a Feature Request
--------------------------------------
Please go to the GitHub Issues page: https://github.com/pynetwork/pypcap/issues.

Checkout the Code
-----------------

::

    git clone https://github.com/pynetwork/pypcap.git


Development notes
-----------------

Regenerating C code
~~~~~~~~~~~~~~~~~~~

The project uses Cython to generate the C code, it's recommended to install it from sources: https://github.com/cython/cython

To regenerate code please use::

    cython pcap.pyx


Building docs
~~~~~~~~~~~~~

To build docs you need the following additional dependencies::

    pip install sphinx mock sphinxcontrib.napoleon


Please use `build_sphinx` task to regenerate the docs::

    python setup.py build_sphinx


Become a Developer
------------------
pypcap uses the 'GitHub Flow' model: `GitHub Flow <http://scottchacon.com/2011/08/31/github-flow.html>`_

- To work on something new, create a descriptively named branch off of master (ie: my-awesome)
- Commit to that branch locally and regularly push your work to the same named branch on the server
- When you need feedback or help, or you think the branch is ready for merging, open a pull request
- After someone else has reviewed and signed off on the feature, you can merge it into master

New Feature or Bug
~~~~~~~~~~~~~~~~~~

    ::

    $ git checkout -b my-awesome
    $ git push -u origin my-awesome
    $ <code for a bit>; git push
    $ <code for a bit>; git push
    $ tox (this will run all the tests)

    - Go to github and hit 'New pull request'
    - Someone reviews it and says 'AOK'
    - Merge the pull request (green button)

