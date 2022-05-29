from setuptools import setup


setup(
    name='instawow_tsmdata',
    py_modules=['instawow_tsmdata'],
    install_requires=[],
    entry_points={
        'instawow.plugins': ['instawow_tsmdata = instawow_tsmdata']
    },
)
