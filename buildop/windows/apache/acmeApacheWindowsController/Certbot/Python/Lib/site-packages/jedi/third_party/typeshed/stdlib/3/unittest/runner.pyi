from typing import Callable, Optional, TextIO, Tuple, Type, Union
import unittest.case
import unittest.result
import unittest.suite


_ResultClassType = Callable[[TextIO, bool, int], unittest.result.TestResult]


class TextTestResult(unittest.result.TestResult):
    separator1: str
    separator2: str
    def __init__(self, stream: TextIO, descriptions: bool,
                 verbosity: int) -> None: ...
    def getDescription(self, test: unittest.case.TestCase) -> str: ...
    def printErrors(self) -> None: ...
    def printErrorList(self, flavour: str, errors: Tuple[unittest.case.TestCase, str]) -> None: ...


class TestRunner:
    def run(self, test: Union[unittest.suite.TestSuite, unittest.case.TestCase]) -> unittest.result.TestResult: ...


class TextTestRunner(TestRunner):
    def __init__(
        self,
        stream: Optional[TextIO] = ...,
        descriptions: bool = ...,
        verbosity: int = ...,
        failfast: bool = ...,
        buffer: bool = ...,
        resultclass: Optional[_ResultClassType] = ...,
        warnings: Optional[Type[Warning]] = ...,
        *,
        tb_locals: bool = ...,
    ) -> None: ...
    def _makeResult(self) -> unittest.result.TestResult: ...
