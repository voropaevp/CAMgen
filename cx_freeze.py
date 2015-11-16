import sys
from cx_Freeze import setup, Executable

base = None
include_files = [r"res/"]
includes = []
excludes = []
packages = ["os", "sys", "re", "jinja2", "argparse"]
setup(name="CAMgen",
      version="0.8",
      description="Cam file generator",
      options={"build_exe": {'excludes': excludes, 'packages': packages, 'include_files': include_files}},
      executables=[Executable(script="main.py", base=base)])
