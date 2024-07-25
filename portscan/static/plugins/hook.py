from PyInstaller.utils.hooks import collect_submodules, collect_data_files


hiddenimports = collect_submodules('pywin32')

datas = collect_data_files('pywin32')
