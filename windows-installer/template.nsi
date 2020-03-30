; This NSIS template is based on the built-in one in pynsist 2.4.
; If pynsist is upgraded, this template may be updated if necessary using the new built-in one.
; Original file can be found here: https://github.com/takluyver/pynsist/blob/2.4/nsist/pyapp.nsi
; Diff file is located at .\template-nsi.patch

; Require the installer do be installed with admin privileges
RequestExecutionLevel admin
; Set default installation path (overridable with /D= flag)
InstallDir "$PROGRAMFILES\Certbot"

!define PRODUCT_NAME "[[ib.appname]]"
!define PRODUCT_VERSION "[[ib.version]]"
!define PY_VERSION "[[ib.py_version]]"
!define PY_MAJOR_VERSION "[[ib.py_major_version]]"
!define BITNESS "[[ib.py_bitness]]"
!define ARCH_TAG "[[arch_tag]]"
!define INSTALLER_NAME "[[ib.installer_name]]"
!define PRODUCT_ICON "[[icon]]"
 
SetCompressor lzma

Function .onInit
  ; Check that Powershell is at least 5.0.
  nsExec::ExecToStack `powershell -ExecutionPolicy RemoteSigned -Command "Write-Host -NoNewline (Get-Host | Select-Object Version).Version.CompareTo([System.Version]'5.0')"`
  Pop $0
  Pop $1
  StrCmp $1 "-1" 0 powershellok
    MessageBox MB_OK|MB_ICONSTOP "Certbot requires Powershell 5.0+ to work.$\r$\nPlease check the following link to know how to upgrade your system:$\r$\nhttps://docs.microsoft.com/powershell/scripting/install/installing-powershell"
    Abort
  powershellok:
FunctionEnd

[% block modernui %]
; Modern UI installer stuff 
!include "MUI2.nsh"
!define MUI_ABORTWARNING
!define MUI_ICON "[[icon]]"
!define MUI_UNICON "[[icon]]"

; UI pages
[% block ui_pages %]
!insertmacro MUI_PAGE_WELCOME
[% if license_file %]
!insertmacro MUI_PAGE_LICENSE [[license_file]]
[% endif %]
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
[% endblock ui_pages %]
!insertmacro MUI_LANGUAGE "English"
[% endblock modernui %]

Name "${PRODUCT_NAME} (beta) ${PRODUCT_VERSION}"
OutFile "${INSTALLER_NAME}"
ShowInstDetails show

Section -SETTINGS
  SetOutPath "$INSTDIR"
  SetOverwrite ifnewer
SectionEnd

[% block sections %]

Section "!${PRODUCT_NAME}" sec_app
  SetRegView [[ib.py_bitness]]
  SetShellVarContext all
  SectionIn RO
  File ${PRODUCT_ICON}
  SetOutPath "$INSTDIR\pkgs"
  File /r "pkgs\*.*"
  SetOutPath "$INSTDIR"

  [% block install_files %]
  ; Install files
  [% for destination, group in grouped_files %]
    SetOutPath "[[destination]]"
    [% for file in group %]
      File "[[ file ]]"
    [% endfor %]
  [% endfor %]
  
  ; Install directories
  [% for dir, destination in ib.install_dirs %]
    SetOutPath "[[ pjoin(destination, dir) ]]"
    File /r "[[dir]]\*.*"
  [% endfor %]
  [% endblock install_files %]
  
  [% block install_shortcuts %]
  ; Install shortcuts
  ; The output path becomes the working directory for shortcuts
  SetOutPath "%HOMEDRIVE%\%HOMEPATH%"
  [% if single_shortcut %]
    [% for scname, sc in ib.shortcuts.items() %]
    CreateShortCut "$SMPROGRAMS\[[scname]].lnk" "[[sc['target'] ]]" \
      '[[ sc['parameters'] ]]' "$INSTDIR\[[ sc['icon'] ]]"
    [% endfor %]
  [% else %]
    [# Multiple shortcuts: create a directory for them #]
    CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
    [% for scname, sc in ib.shortcuts.items() %]
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\[[scname]].lnk" "[[sc['target'] ]]" \
      '[[ sc['parameters'] ]]' "$INSTDIR\[[ sc['icon'] ]]"
    [% endfor %]
  [% endif %]
  SetOutPath "$INSTDIR"
  [% endblock install_shortcuts %]

  [% block install_commands %]
  [% if has_commands %]
    DetailPrint "Setting up command-line launchers..."
    nsExec::ExecToLog '[[ python ]] -Es "$INSTDIR\_assemble_launchers.py" [[ python ]] "$INSTDIR\bin"'

    ; Add to PATH for all users
    nsExec::ExecToLog '[[ python ]] -Es "$INSTDIR\_system_path.py" add "$INSTDIR\bin"'
  [% endif %]
  [% endblock install_commands %]
  
  ; Byte-compile Python files.
  DetailPrint "Byte-compiling Python modules..."
  nsExec::ExecToLog '[[ python ]] -m compileall -q "$INSTDIR\pkgs"'
  WriteUninstaller $INSTDIR\uninstall.exe
  ; Add ourselves to Add/remove programs
  WriteRegStr SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
                   "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
                   "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
                   "InstallLocation" "$INSTDIR"
  WriteRegStr SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
                   "DisplayIcon" "$INSTDIR\${PRODUCT_ICON}"
  [% if ib.publisher is not none %]
    WriteRegStr SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
                     "Publisher" "[[ib.publisher]]"
  [% endif %]
  WriteRegStr SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
                   "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegDWORD SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
                   "NoModify" 1
  WriteRegDWORD SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
                   "NoRepair" 1

  ; Execute ps script to create the certbot renew & auto-update task
  DetailPrint "Setting up certbot renew & auto-update scheduled task"
  nsExec::ExecToLog 'powershell -inputformat none -ExecutionPolicy RemoteSigned -File "$INSTDIR\tasks-up.ps1" -InstallDir "$INSTDIR"'

  ; Check if we need to reboot
  IfRebootFlag 0 noreboot
    MessageBox MB_YESNO "A reboot is required to finish the installation. Do you wish to reboot now?" \
                /SD IDNO IDNO noreboot
      Reboot
  noreboot:
SectionEnd

Section "Uninstall"
  SetRegView [[ib.py_bitness]]
  SetShellVarContext all

  ; Execute ps script to remove the certbot renew & auto-update task, then delete scripts
  nsExec::ExecToLog 'powershell -inputformat none -ExecutionPolicy RemoteSigned -File "$INSTDIR\tasks-down.ps1"'
  Delete "$INSTDIR\tasks-down.ps1"
  Delete "$INSTDIR\tasks-up.ps1"
  Delete "$INSTDIR\auto-update.ps1"

  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\${PRODUCT_ICON}"
  RMDir /r "$INSTDIR\pkgs"

  ; Remove ourselves from %PATH%
  [% block uninstall_commands %]
  [% if has_commands %]
    nsExec::ExecToLog '[[ python ]] -Es "$INSTDIR\_system_path.py" remove "$INSTDIR\bin"'
  [% endif %]
  [% endblock uninstall_commands %]

  [% block uninstall_files %]
  ; Uninstall files
  [% for file, destination in ib.install_files %]
    Delete "[[pjoin(destination, file)]]"
  [% endfor %]
  ; Uninstall directories
  [% for dir, destination in ib.install_dirs %]
    RMDir /r "[[pjoin(destination, dir)]]"
  [% endfor %]
  [% endblock uninstall_files %]

  [% block uninstall_shortcuts %]
  ; Uninstall shortcuts
  [% if single_shortcut %]
    [% for scname in ib.shortcuts %]
      Delete "$SMPROGRAMS\[[scname]].lnk"
    [% endfor %]
  [% else %]
    RMDir /r "$SMPROGRAMS\${PRODUCT_NAME}"
  [% endif %]
  [% endblock uninstall_shortcuts %]
  RMDir $INSTDIR
  DeleteRegKey SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
SectionEnd

[% endblock sections %]

; Functions

Function .onMouseOverSection
    ; Find which section the mouse is over, and set the corresponding description.
    FindWindow $R0 "#32770" "" $HWNDPARENT
    GetDlgItem $R0 $R0 1043 ; description item (must be added to the UI)

    [% block mouseover_messages %]
    StrCmp $0 ${sec_app} "" +2
      SendMessage $R0 ${WM_SETTEXT} 0 "STR:${PRODUCT_NAME}"
    
    [% endblock mouseover_messages %]
FunctionEnd
