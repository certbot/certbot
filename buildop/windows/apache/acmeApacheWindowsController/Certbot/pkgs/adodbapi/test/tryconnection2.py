# This module may be retired as soon as Python 2.5 support is dropped.
#
# It exists only to allow trapping exceptions using the "except [exception list], e" format
# which is a syntax error in Python 3

def try_connection(verbose, *args, **kwargs):
    import adodbapi

    if "proxy_host" in kwargs or 'pyro_connection' in kwargs or 'proxy_host' in args:
        import adodbapi.remote
        import Pyro4
        pyroError = Pyro4.errors.PyroError
        dbconnect = adodbapi.remote.connect
        remote = True
    else:
        dbconnect = adodbapi.connect
        pyroError = NotImplementedError  # (will not occur)
        remote = False
    try:
        s = dbconnect(*args, **kwargs) # connect to server
        if verbose:
            print('Connected to:', s.connection_string)
            print('which has tables:', s.get_table_names())
        s.close()  # thanks, it worked, goodbye
    except (adodbapi.DatabaseError, pyroError) as inst:
        print(inst.args[0])   # should be the error message
        print('***Failed getting connection using=', repr(args), repr(kwargs))
        if remote:
            print('** Is your Python2 ado.connection server running?')
            print('* Have you run "setuptestframework.py" to create server_test.mdb?')
        return False, (args, kwargs), None

    if remote:
        print("  (remote)", end=' ')
    print("  (successful)")

    return True, (args, kwargs, remote), dbconnect

def try_operation_with_expected_exception(expected_exceptions, some_function, args, kwargs):
    try:
        some_function(*args, **kwargs)
    except expected_exceptions as e:
        return True, e
    except:
        raise  # an exception other than the expected occurred
    return False, 'The expected exception did not occur'
