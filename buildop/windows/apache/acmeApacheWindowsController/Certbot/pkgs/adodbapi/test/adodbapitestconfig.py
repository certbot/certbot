# Configure this to _YOUR_ environment in order to run the testcases.
"testADOdbapiConfig.py v 2.6.0.A00"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# #
# #  TESTERS:
# #
# #  You will need to make numerous modifications to this file
# #  to adapt it to your own testing environment.
# #
# #  Skip down to the next "# #" line --
# #  -- the things you need to change are below it.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
import platform
import sys
import random

import is64bit
import setuptestframework
if sys.version_info >= (3,0):
    import tryconnection3 as tryconnection
else:
    import tryconnection2 as tryconnection

print((sys.version))
node = platform.node()
try: print(('node=%s: is64bit.os()= %s, is64bit.Python()= %s' % (node, is64bit.os(), is64bit.Python())))
except: pass

try:
    onWindows = bool(sys.getwindowsversion()) # seems to work on all versions of Python
except:
    onWindows = False

# create a random name for temporary table names
_alphabet = "PYFGCRLAOEUIDHTNTQJKXBMWVZ1234567890" # yes, I do use a dvorak keyboard!
tmp = ''.join([random.choice(_alphabet) for x in range(9)])
mdb_name = 'xx_' + tmp + '.mdb'
testfolder = setuptestframework.maketemp()

if '--package' in sys.argv:
    pth = setuptestframework.makeadopackage(testfolder)
else:
    pth = setuptestframework.find_ado_path()
if pth not in sys.path:
    sys.path.insert(1,pth)

# function to clean up the temporary folder -- calling program must run this function before exit.
cleanup = setuptestframework.getcleanupfunction()

import adodbapi  # will (hopefully) be imported using the "pth" discovered above

try:
    print((adodbapi.version)) # show version
except:
    print('"adodbapi.version" not present or not working.')
print(__doc__)

verbose = False
for a in sys.argv:
    if a.startswith('--verbose'):
        arg = True
        try: arg = int(a.split("=")[1])
        except IndexError: pass
        adodbapi.adodbapi.verbose = arg
        verbose = arg

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # start your environment setup here v v v
SQL_HOST_NODE = 'Vpad'
doAllTests = '--all' in sys.argv
doAccessTest = not ('--nojet' in sys.argv)
doSqlServerTest = node == SQL_HOST_NODE or '--mssql' in  sys.argv or doAllTests
doMySqlTest = '--mysql' in sys.argv or doAllTests
doPostgresTest = '--pg' in sys.argv or doAllTests
iterateOverTimeTests = ('--time' in sys.argv or doAllTests) and onWindows

THE_PROXY_HOST = '25.44.77.176' if node != SQL_HOST_NODE or not onWindows else '::1' # -- change this

try: #If mx extensions are installed, use mxDateTime
    import mx.DateTime
    doMxDateTimeTest=True
except: 
    doMxDateTimeTest=False #Requires eGenixMXExtensions

doTimeTest = True # obsolete python time format

if doAccessTest:
    if onWindows and (node == SQL_HOST_NODE or not is64bit.Python()):
        c = {'mdb': setuptestframework.makemdb(testfolder, mdb_name)}
    else:
        c = {'macro_find_temp_test_path' : ['mdb', 'server_test.mdb'],
            'proxy_host' : THE_PROXY_HOST}


    # macro definition for keyword "driver"  using macro "is64bit" -- see documentation
    c['macro_is64bit'] = ['driver', "Microsoft.ACE.OLEDB.12.0", "Microsoft.Jet.OLEDB.4.0"]
    connStrAccess = "Provider=%(driver)s;Data Source=%(mdb)s"
    print('    ...Testing ACCESS connection...')
    doAccessTest, connStrAccess, dbAccessconnect = tryconnection.try_connection(verbose, connStrAccess, 10, **c)

if doSqlServerTest:
    c = {'macro_getnode' : ['host', r"%s\SQLExpress"],  # name of computer with SQL Server
        #'host':'25.44.77.176;' # Network Library=dbmssocn',
        'database': "adotest",
        'user' : 'adotestuser',   # None implies Windows security
        'password' : "12345678",
        # macro definition for keyword "security" using macro "auto_security"
        'macro_auto_security' : 'security',
        'provider' : 'SQLNCLI11; MARS Connection=True'
         }
    connStr = "Provider=%(provider)s; Initial Catalog=%(database)s; Data Source=%(host)s; %(security)s;"

    if node != SQL_HOST_NODE:
        if THE_PROXY_HOST:
            c["proxy_host"] = THE_PROXY_HOST  # the SQL server runs a proxy for this test
        else:
            c["pyro_connection"] = "PYRONAME:ado.connection"
    print('    ...Testing MS-SQL login...')
    doSqlServerTest, connStrSQLServer, dbSqlServerconnect = tryconnection.try_connection(verbose, connStr, 30, **c)

if doMySqlTest:
    c = {'host' : "25.223.161.222",
        'database' : 'test',
        'user' : 'adotest',
        'password' : '12345678',
        'driver' : "MySQL ODBC 5.3 Unicode Driver"}    # or _driver="MySQL ODBC 3.51 Driver

    if not onWindows:
        if THE_PROXY_HOST:
            c["proxy_host"] = THE_PROXY_HOST
        else:
            c["pyro_connection"] = "PYRONAME:ado.connection"

    c['macro_is64bit'] = ['provider', 'Provider=MSDASQL;']
    cs = '%(provider)sDriver={%(driver)s};Server=%(host)s;Port=3306;' + \
        'Database=%(database)s;user=%(user)s;password=%(password)s;Option=3;'
    print('    ...Testing MySql login...')
    doMySqlTest, connStrMySql, dbMySqlconnect = tryconnection.try_connection(verbose, cs, 5, **c)

if doPostgresTest:
    _computername = "25.223.161.222"
    _databasename='adotest'
    _username = 'adotestuser'
    _password = '12345678'
    kws = {'timeout' : 4}
    kws['macro_is64bit'] = ['prov_drv', 'Provider=MSDASQL;Driver={PostgreSQL Unicode(x64)}',
        'Driver=PostgreSQL Unicode']
    if not onWindows:
        if THE_PROXY_HOST:
            kws['proxy_host'] = THE_PROXY_HOST
        else:
            kws['pyro_connection'] = 'PYRONAME:ado.connection'
    # get driver from http://www.postgresql.org/ftp/odbc/versions/
    # test using positional and keyword arguments (bad example for real code)
    print('    ...Testing PostgreSQL login...')
    doPostgresTest, connStrPostgres, dbPostgresConnect = tryconnection.try_connection(verbose,
        '%(prov_drv)s;Server=%(host)s;Database=%(database)s;uid=%(user)s;pwd=%(password)s;',
         _username, _password, _computername, _databasename, **kws)

assert doAccessTest or doSqlServerTest or doMySqlTest or doPostgresTest, 'No database engine found for testing'
