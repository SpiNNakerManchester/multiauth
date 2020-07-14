from setuptools import setup, find_packages

requirements = [
    'oauthenticator>=0.9.0',
]

setup(
    name='multiauthenticator',
    version='0.1.0',
    description='Authenticates using multiple protocols',
    author='UoM',
    author_email='support@humanbrainproject.eu',
    url='https://wiki.humanbrainproject.eu/',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    install_requires=requirements
)
