; This NSIS template is based on the built-in one in pynsist 2.3.
; Added lines are enclosed within "CERTBOT CUSTOM BEGIN/END" comments.
; If pynsist is upgraded, this template must be updated if necessary using the new built-in one.
; Original file can be found here: https://github.com/takluyver/pynsist/blob/2.4/nsist/pyapp.nsi

!define PRODUCT_NAME "[[ib.appname]]"
!define PRODUCT_VERSION "[[ib.version]]"
!define PY_VERSION "[[ib.py_version]]"
!define PY_MAJOR_VERSION "[[ib.py_major_version]]"
!define BITNESS "[[ib.py_bitness]]"
!define ARCH_TAG "[[arch_tag]]"
!define INSTALLER_NAME "[[ib.installer_name]]"
!define PRODUCT_ICON "[[icon]]"

; Marker file to tell the uninstaller that it's a user installation
!define USER_INSTALL_MARKER _user_install_marker
 
SetCompressor lzma

; CERTBOT CUSTOM BEGIN
; Administrator privileges are required to insert a new task in Windows Scheduler.
; Also comment out some options to disable ability to choose AllUsers/CurrentUser install mode.
; As a result, installer run always with admin privileges (because of MULTIUSER_EXECUTIONLEVEL),
; using the AllUsers installation mode by default (because of MULTIUSER_INSTALLMODE_DEFAULT_CURRENTUSER
; not set), and this default behavior cannot be overridden (because of MULTIUSER_MUI not set).
; See https://nsis.sourceforge.io/Docs/MultiUser/Readme.html
!define MULTIUSER_EXECUTIONLEVEL Admin
;!define MULTIUSER_EXECUTIONLEVEL Highest
;!define MULTIUSER_INSTALLMODE_DEFAULT_CURRENTUSER
;!define MULTIUSER_MUI
;!define MULTIUSER_INSTALLMODE_COMMANDLINE
; CERTBOT CUSTOM END
!define MULTIUSER_INSTALLMODE_INSTDIR "[[ib.appname]]"
[% if ib.py_bitness == 64 %]
!define MULTIUSER_INSTALLMODE_FUNCTION correct_prog_files
[% endif %]
!include MultiUser.nsh

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
; CERTBOT CUSTOM BEGIN
; Disable the installation mode page (AllUsers/CurrentUser)
;!insertmacro MULTIUSER_PAGE_INSTALLMODE
; CERTBOT CUSTOM END
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
[% endblock ui_pages %]
!insertmacro MUI_LANGUAGE "English"
[% endblock modernui %]

; CERTBOT CUSTOM BEGIN
Name "${PRODUCT_NAME} (beta) ${PRODUCT_VERSION}"
;Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
; CERTBOT CUSTOM END
OutFile "${INSTALLER_NAME}"
ShowInstDetails show

Section -SETTINGS
  SetOutPath "$INSTDIR"
  SetOverwrite ifnewer
SectionEnd

[% block sections %]

Section "!${PRODUCT_NAME}" sec_app
  SetRegView [[ib.py_bitness]]
  SectionIn RO
  File ${PRODUCT_ICON}
  SetOutPath "$INSTDIR\pkgs"
  File /r "pkgs\*.*"
  SetOutPath "$INSTDIR"

  ; Marker file for per-user install
  StrCmp $MultiUser.InstallMode CurrentUser 0 +3
    FileOpen $0 "$INSTDIR\${USER_INSTALL_MARKER}" w
    FileClose $0
    SetFileAttributes "$INSTDIR\${USER_INSTALL_MARKER}" HIDDEN

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

    StrCmp $MultiUser.InstallMode CurrentUser 0 AddSysPathSystem
      ; Add to PATH for current user
      nsExec::ExecToLog '[[ python ]] -Es "$INSTDIR\_system_path.py" add_user "$INSTDIR\bin"'
      GoTo AddedSysPath
    AddSysPathSystem:
      ; Add to PATH for all users
      nsExec::ExecToLog '[[ python ]] -Es "$INSTDIR\_system_path.py" add "$INSTDIR\bin"'
    AddedSysPath:
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

  ; CERTBOT CUSTOM BEGIN
  ; Execute ps script to create the certbot renew task
  DetailPrint "Setting up certbot renew scheduled task"
  nsExec::ExecToStack 'powershell -inputformat none -ExecutionPolicy RemoteSigned -File "$INSTDIR\renew-up.ps1"'
  ; CERTBOT CUSTOM END

  ; Check if we need to reboot
  IfRebootFlag 0 noreboot
    MessageBox MB_YESNO "A reboot is required to finish the installation. Do you wish to reboot now?" \
                /SD IDNO IDNO noreboot
      Reboot
  noreboot:
SectionEnd

Section "Uninstall"
  ; CERTBOT CUSTOM BEGIN
  ; Execute ps script to remove the certbot renew task
  nsExec::ExecToStack 'powershell -inputformat none -ExecutionPolicy RemoteSigned -File "$INSTDIR\renew-down.ps1"'
  ; CERTBOT CUSTOM END

  SetRegView [[ib.py_bitness]]
  SetShellVarContext all
  IfFileExists "$INSTDIR\${USER_INSTALL_MARKER}" 0 +3
    SetShellVarContext current
    Delete "$INSTDIR\${USER_INSTALL_MARKER}"

  Delete $INSTDIR\uninstall.exe
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

Function .onInit
  !insertmacro MULTIUSER_INIT
FunctionEnd

Function un.onInit
  !insertmacro MULTIUSER_UNINIT
FunctionEnd

[% if ib.py_bitness == 64 %]
Function correct_prog_files
  ; The multiuser machinery doesn't know about the different Program files
  ; folder for 64-bit applications. Override the install dir it set.
  StrCmp $MultiUser.InstallMode AllUsers 0 +2
    StrCpy $INSTDIR "$PROGRAMFILES64\${MULTIUSER_INSTALLMODE_INSTDIR}"
FunctionEnd
[% endif %]