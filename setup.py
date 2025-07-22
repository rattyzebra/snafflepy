from setuptools import setup, find_namespace_packages
import os

# The directory containing this file
HERE = os.path.abspath(os.path.dirname(__file__))

# The text of the README file
with open(os.path.join(HERE, "README.md")) as f:
    README = f.read()

# The text of the requirements file
with open(os.path.join(HERE, "requirements.txt")) as f:
    requirements = f.read().splitlines()

setup(
    name='snafflepy',
    version='0.1.0',
    description='A python port of Snaffler',
    long_description=README,
    long_description_content_type='text/markdown',
    author='Robert Todora',
    author_email='robert.todora@protonmail.com',
    url='https://github.com/robert-todora/snafflepy',
    py_modules=['snaffler'],
    packages=find_namespace_packages(),
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'snafflepy = snaffler:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
