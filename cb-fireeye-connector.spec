a = Analysis(['scripts/cb-fireeye-connector'],
             pathex=['.'],
             hiddenimports=['unicodedata', 'requests'],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='cb-fireeye-connector',
          debug=False,
          strip=False,
          upx=True,
          console=True )