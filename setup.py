from setuptools import setup

setup(
    name='jupyterhub-hashauthenticator',
    version='0.4.1',
    description='Hashed Password Authenticator for JupyterHub',
    url='https://github.com/thedataincubator/jupyterhub-hashauthenticator',
    author='Petko Minkov',
    author_email='pminkov@gmail.com',
    maintainer='Robert Schroll',
    maintainer_email='robert@thedataincubator.com',
    scripts=['scripts/hashauthpw'],
    install_requires=['jupyterhub', 'tornado', 'traitlets', 'oauthenticator'],
    test_suite="hashauthenticator.tests",
    license='BSD3',
    packages=['hashauthenticator'],
)
