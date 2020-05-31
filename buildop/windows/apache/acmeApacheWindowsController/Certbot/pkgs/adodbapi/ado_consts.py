# ADO enumerated constants documented on MSDN:
# http://msdn.microsoft.com/en-us/library/ms678353(VS.85).aspx

# IsolationLevelEnum
adXactUnspecified     = -1
adXactBrowse          = 0x100
adXactChaos           = 0x10
adXactCursorStability = 0x1000
adXactIsolated        = 0x100000
adXactReadCommitted   = 0x1000
adXactReadUncommitted = 0x100
adXactRepeatableRead  = 0x10000
adXactSerializable    = 0x100000

# CursorLocationEnum
adUseClient = 3
adUseServer = 2

# CursorTypeEnum
adOpenDynamic       = 2
adOpenForwardOnly   = 0
adOpenKeyset        = 1
adOpenStatic        = 3
adOpenUnspecified   = -1

# CommandTypeEnum
adCmdText = 1
adCmdStoredProc = 4
adSchemaTables = 20

# ParameterDirectionEnum
adParamInput       = 1
adParamInputOutput = 3
adParamOutput      = 2
adParamReturnValue = 4
adParamUnknown     = 0
directions = {
        0: 'Unknown',
        1: 'Input',
        2: 'Output',
        3: 'InputOutput',
        4: 'Return',
    }
def ado_direction_name(ado_dir):
    try:
        return 'adParam' + directions[ado_dir]
    except:
        return 'unknown direction ('+str(ado_dir)+')'

# ObjectStateEnum
adStateClosed     = 0
adStateOpen       = 1
adStateConnecting = 2
adStateExecuting  = 4
adStateFetching   = 8

# FieldAttributeEnum
adFldMayBeNull = 0x40

# ConnectModeEnum
adModeUnknown           = 0
adModeRead              = 1
adModeWrite             = 2
adModeReadWrite         = 3
adModeShareDenyRead     = 4
adModeShareDenyWrite    = 8
adModeShareExclusive    = 12
adModeShareDenyNone     = 16
adModeRecursive         = 0x400000

# XactAttributeEnum
adXactCommitRetaining = 131072
adXactAbortRetaining = 262144

ado_error_TIMEOUT = -2147217871

# DataTypeEnum - ADO Data types documented at:
# http://msdn2.microsoft.com/en-us/library/ms675318.aspx
adArray                       = 0x2000
adEmpty                       = 0x0
adBSTR                        = 0x8
adBigInt                      = 0x14
adBinary                      = 0x80
adBoolean                     = 0xb
adChapter                     = 0x88
adChar                        = 0x81
adCurrency                    = 0x6
adDBDate                      = 0x85
adDBTime                      = 0x86
adDBTimeStamp                 = 0x87
adDate                        = 0x7
adDecimal                     = 0xe
adDouble                      = 0x5
adError                       = 0xa
adFileTime                    = 0x40
adGUID                        = 0x48
adIDispatch                   = 0x9
adIUnknown                    = 0xd
adInteger                     = 0x3
adLongVarBinary               = 0xcd
adLongVarChar                 = 0xc9
adLongVarWChar                = 0xcb
adNumeric                     = 0x83
adPropVariant                 = 0x8a
adSingle                      = 0x4
adSmallInt                    = 0x2
adTinyInt                     = 0x10
adUnsignedBigInt              = 0x15
adUnsignedInt                 = 0x13
adUnsignedSmallInt            = 0x12
adUnsignedTinyInt             = 0x11
adUserDefined                 = 0x84
adVarBinary                   = 0xCC
adVarChar                     = 0xC8
adVarNumeric                  = 0x8B
adVarWChar                    = 0xCA
adVariant                     = 0xC
adWChar                       = 0x82
# Additional constants used by introspection but not ADO itself
AUTO_FIELD_MARKER = -1000

adTypeNames = {
    adBSTR: 'adBSTR',
    adBigInt: 'adBigInt',
    adBinary: 'adBinary',
    adBoolean: 'adBoolean',
    adChapter: 'adChapter',
    adChar: 'adChar',
    adCurrency: 'adCurrency',
    adDBDate: 'adDBDate',
    adDBTime: 'adDBTime',
    adDBTimeStamp: 'adDBTimeStamp',
    adDate: 'adDate',
    adDecimal: 'adDecimal',
    adDouble: 'adDouble',
    adEmpty: 'adEmpty',
    adError: 'adError',
    adFileTime: 'adFileTime',
    adGUID: 'adGUID',
    adIDispatch: 'adIDispatch',
    adIUnknown: 'adIUnknown',
    adInteger: 'adInteger',
    adLongVarBinary: 'adLongVarBinary',
    adLongVarChar: 'adLongVarChar',
    adLongVarWChar: 'adLongVarWChar',
    adNumeric: 'adNumeric',
    adPropVariant: 'adPropVariant',
    adSingle: 'adSingle',
    adSmallInt: 'adSmallInt',
    adTinyInt: 'adTinyInt',
    adUnsignedBigInt: 'adUnsignedBigInt',
    adUnsignedInt: 'adUnsignedInt',
    adUnsignedSmallInt: 'adUnsignedSmallInt',
    adUnsignedTinyInt: 'adUnsignedTinyInt',
    adUserDefined: 'adUserDefined',
    adVarBinary: 'adVarBinary',
    adVarChar: 'adVarChar',
    adVarNumeric: 'adVarNumeric',
    adVarWChar: 'adVarWChar',
    adVariant: 'adVariant',
    adWChar: 'adWChar',
   }

def ado_type_name(ado_type):
    return adTypeNames.get(ado_type, 'unknown type ('+str(ado_type)+')')

# here in decimal, sorted by value
#adEmpty 0 Specifies no value (DBTYPE_EMPTY). 
#adSmallInt 2 Indicates a two-byte signed integer (DBTYPE_I2). 
#adInteger 3 Indicates a four-byte signed integer (DBTYPE_I4). 
#adSingle 4 Indicates a single-precision floating-point value (DBTYPE_R4). 
#adDouble 5 Indicates a double-precision floating-point value (DBTYPE_R8). 
#adCurrency 6 Indicates a currency value (DBTYPE_CY). Currency is a fixed-point number
#   with four digits to the right of the decimal point. It is stored in an eight-byte signed integer scaled by 10,000.
#adDate 7 Indicates a date value (DBTYPE_DATE). A date is stored as a double, the whole part of which is
#   the number of days since December 30, 1899, and the fractional part of which is the fraction of a day.
#adBSTR 8 Indicates a null-terminated character string (Unicode) (DBTYPE_BSTR). 
#adIDispatch 9 Indicates a pointer to an IDispatch interface on a COM object (DBTYPE_IDISPATCH). 
#adError 10 Indicates a 32-bit error code (DBTYPE_ERROR). 
#adBoolean 11 Indicates a boolean value (DBTYPE_BOOL). 
#adVariant 12 Indicates an Automation Variant (DBTYPE_VARIANT). 
#adIUnknown 13 Indicates a pointer to an IUnknown interface on a COM object (DBTYPE_IUNKNOWN). 
#adDecimal 14 Indicates an exact numeric value with a fixed precision and scale (DBTYPE_DECIMAL). 
#adTinyInt 16 Indicates a one-byte signed integer (DBTYPE_I1). 
#adUnsignedTinyInt 17 Indicates a one-byte unsigned integer (DBTYPE_UI1). 
#adUnsignedSmallInt 18 Indicates a two-byte unsigned integer (DBTYPE_UI2). 
#adUnsignedInt 19 Indicates a four-byte unsigned integer (DBTYPE_UI4). 
#adBigInt 20 Indicates an eight-byte signed integer (DBTYPE_I8). 
#adUnsignedBigInt 21 Indicates an eight-byte unsigned integer (DBTYPE_UI8). 
#adFileTime 64 Indicates a 64-bit value representing the number of 100-nanosecond intervals since
#    January 1, 1601 (DBTYPE_FILETIME).
#adGUID 72 Indicates a globally unique identifier (GUID) (DBTYPE_GUID). 
#adBinary 128 Indicates a binary value (DBTYPE_BYTES). 
#adChar 129 Indicates a string value (DBTYPE_STR). 
#adWChar 130 Indicates a null-terminated Unicode character string (DBTYPE_WSTR). 
#adNumeric 131 Indicates an exact numeric value with a fixed precision and scale (DBTYPE_NUMERIC).
#   adUserDefined 132 Indicates a user-defined variable (DBTYPE_UDT).
#adUserDefined 132 Indicates a user-defined variable (DBTYPE_UDT). 
#adDBDate 133 Indicates a date value (yyyymmdd) (DBTYPE_DBDATE). 
#adDBTime 134 Indicates a time value (hhmmss) (DBTYPE_DBTIME). 
#adDBTimeStamp 135 Indicates a date/time stamp (yyyymmddhhmmss plus a fraction in billionths) (DBTYPE_DBTIMESTAMP). 
#adChapter 136 Indicates a four-byte chapter value that identifies rows in a child rowset (DBTYPE_HCHAPTER). 
#adPropVariant 138 Indicates an Automation PROPVARIANT (DBTYPE_PROP_VARIANT). 
#adVarNumeric 139 Indicates a numeric value (Parameter object only). 
#adVarChar 200 Indicates a string value (Parameter object only). 
#adLongVarChar 201 Indicates a long string value (Parameter object only). 
#adVarWChar 202 Indicates a null-terminated Unicode character string (Parameter object only). 
#adLongVarWChar 203 Indicates a long null-terminated Unicode string value (Parameter object only). 
#adVarBinary 204 Indicates a binary value (Parameter object only). 
#adLongVarBinary 205 Indicates a long binary value (Parameter object only). 
#adArray (Does not apply to ADOX.) 0x2000 A flag value, always combined with another data type constant,
#   that indicates an array of that other data type.

# Error codes to names
adoErrors= {
    0xe7b      :'adErrBoundToCommand',
    0xe94      :'adErrCannotComplete',
    0xea4      :'adErrCantChangeConnection',
    0xc94      :'adErrCantChangeProvider',
    0xe8c      :'adErrCantConvertvalue',
    0xe8d      :'adErrCantCreate',
    0xea3      :'adErrCatalogNotSet',
    0xe8e      :'adErrColumnNotOnThisRow',
    0xd5d      :'adErrDataConversion',
    0xe89      :'adErrDataOverflow',
    0xe9a      :'adErrDelResOutOfScope',
    0xea6      :'adErrDenyNotSupported',
    0xea7      :'adErrDenyTypeNotSupported',
    0xcb3      :'adErrFeatureNotAvailable',
    0xea5      :'adErrFieldsUpdateFailed',
    0xc93      :'adErrIllegalOperation',
    0xcae      :'adErrInTransaction',
    0xe87      :'adErrIntegrityViolation',
    0xbb9      :'adErrInvalidArgument',
    0xe7d      :'adErrInvalidConnection',
    0xe7c      :'adErrInvalidParamInfo',
    0xe82      :'adErrInvalidTransaction',
    0xe91      :'adErrInvalidURL',
    0xcc1      :'adErrItemNotFound',
    0xbcd      :'adErrNoCurrentRecord',
    0xe83      :'adErrNotExecuting',
    0xe7e      :'adErrNotReentrant',
    0xe78      :'adErrObjectClosed',
    0xd27      :'adErrObjectInCollection',
    0xd5c      :'adErrObjectNotSet',
    0xe79      :'adErrObjectOpen',
    0xbba      :'adErrOpeningFile',
    0xe80      :'adErrOperationCancelled',
    0xe96      :'adErrOutOfSpace',
    0xe88      :'adErrPermissionDenied',
    0xe9e      :'adErrPropConflicting',
    0xe9b      :'adErrPropInvalidColumn',
    0xe9c      :'adErrPropInvalidOption',
    0xe9d      :'adErrPropInvalidValue',
    0xe9f      :'adErrPropNotAllSettable',
    0xea0      :'adErrPropNotSet',
    0xea1      :'adErrPropNotSettable',
    0xea2      :'adErrPropNotSupported',
    0xbb8      :'adErrProviderFailed',
    0xe7a      :'adErrProviderNotFound',
    0xbbb      :'adErrReadFile',
    0xe93      :'adErrResourceExists',
    0xe92      :'adErrResourceLocked',
    0xe97      :'adErrResourceOutOfScope',
    0xe8a      :'adErrSchemaViolation',
    0xe8b      :'adErrSignMismatch',
    0xe81      :'adErrStillConnecting',
    0xe7f      :'adErrStillExecuting',
    0xe90      :'adErrTreePermissionDenied',
    0xe8f      :'adErrURLDoesNotExist',
    0xe99      :'adErrURLNamedRowDoesNotExist',
    0xe98      :'adErrUnavailable',
    0xe84      :'adErrUnsafeOperation',
    0xe95      :'adErrVolumeNotFound',
    0xbbc      :'adErrWriteFile'
    }
