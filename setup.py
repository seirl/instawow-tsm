from setuptools import setup


setup(
    name='instawow_tsm',
    py_modules=['instawow_tsm'],
    install_requires=[],
    entry_points={
        'instawow.plugins': ['instawow_tsm = instawow_tsm']
    },
)
