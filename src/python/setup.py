from setuptools import setup, find_packages
setup(
    name='blackfyre',
    version='1.0.1',
    description='Your package description',
    author='Malachi Jones',
    author_email='malachi.jones@jonescyber-ai.com',
    url='https://github.com/jonescyber-ai/Blackfyre/',
    packages=find_packages(include=["blackfyre"]),
    package_data={},
    install_requires=[
        "pyvex==9.2.78",
        "protobuf==4.25.1",
        "numpy==2.2.6",
        "omegaconf",
    ],
    extras_require={
        "test": [
            "pytest>=7.0.0",
        ],
    },
)
