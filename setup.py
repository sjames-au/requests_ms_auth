from setuptools import setup, find_packages

version=open('VERSION').read().strip()

setup(
    name='requests-adal-auth',
    version=version,
    packages=find_packages(exclude=['tests*']),
    license='AGPL-3.0',
    description='Python requests session with support for oauth and adal',
    long_description=open('README.md').read(),
    install_requires=['requests-adal-auth'],
    url='https://github.com/equinor/requests-adal-auth',
    download_url=f"https://github.com/equinor/requests-adal-auth/dist/requests-adal-auth-{version}.tar.gz",
    author='Lennart Rolland',
    author_email='lennartrolland@gmail.com',
    classifiers=[
        "Intended Audience :: Developers",
        "Topic :: Utilities",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
)

