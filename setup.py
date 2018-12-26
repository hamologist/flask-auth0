from setuptools import find_packages, setup

setup(
    name='flask-auth0',
    version='0.1',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        'flask>=1.0',
        'auth0-python>=3.4',
        'python-dotenv>=0.10',
        'requests>=2.20',
        'python-jose>=3.0',
    ]
)
