from setuptools import setup

setup(
    name='pymyna',
    version='1.0',
    description='Python interface for My Number Card operation.',
    url='http://github.com/hebingchang/pymyna',
    author='hebingchang',
    author_email='hebingchang@sjtu.edu.cn',
    license='MIT',
    packages=['myna'],
    install_requires=[
    ],
    zip_safe=False,
    entry_points={
        'console_scripts': ['myna=myna.cmd.myna_cli:main'],
    }
)
