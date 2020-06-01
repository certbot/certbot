# Stubs for _subprocess

# NOTE: These are incomplete!

from typing import Mapping, Any, Tuple

CREATE_NEW_CONSOLE: int
CREATE_NEW_PROCESS_GROUP: int
STD_INPUT_HANDLE: int
STD_OUTPUT_HANDLE: int
STD_ERROR_HANDLE: int
SW_HIDE: int
STARTF_USESTDHANDLES: int
STARTF_USESHOWWINDOW: int
INFINITE: int
DUPLICATE_SAME_ACCESS: int
WAIT_OBJECT_0: int

# TODO not exported by the Python module
class Handle:
    def Close(self) -> None: ...

def GetVersion() -> int: ...
def GetExitCodeProcess(handle: Handle) -> int: ...
def WaitForSingleObject(handle: Handle, timeout: int) -> int: ...
def CreateProcess(executable: str, cmd_line: str,
                  proc_attrs, thread_attrs,
                  inherit: int, flags: int,
                  env_mapping: Mapping[str, str],
                  curdir: str,
                  startupinfo: Any) -> Tuple[Any, Handle, int, int]: ...
def GetModuleFileName(module: int) -> str: ...
def GetCurrentProcess() -> Handle: ...
def DuplicateHandle(source_proc: Handle, source: Handle, target_proc: Handle,
                    target: Any, access: int, inherit: int) -> int: ...
def CreatePipe(pipe_attrs, size: int) -> Tuple[Handle, Handle]: ...
def GetStdHandle(arg: int) -> int: ...
def TerminateProcess(handle: Handle, exit_code: int) -> None: ...
