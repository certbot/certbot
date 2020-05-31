from __future__ import with_statement  # needed only if running Python 2.5
import adodbapi
try:
    import adodbapi.is64bit as is64bit
    is64 = is64bit.Python()
except ImportError:
    is64 = False  # in case the user has an old version of adodbapi
if is64:
    driver = "Microsoft.ACE.OLEDB.12.0"
else:
    driver = "Microsoft.Jet.OLEDB.4.0"
filename = 'xx.xls'  # file will be created if it does not exist
extended = 'Extended Properties="Excel 8.0;Readonly=False;"'

constr = "Provider=%s;Data Source=%s;%s" % (driver, filename, extended)

conn = adodbapi.connect(constr)
with conn: # will auto commit if no errors
    with conn.cursor() as crsr:
        try:    crsr.execute('drop table SheetOne')
        except: pass  # just is case there is one already there

        # create the sheet and the header row and set the types for the columns
        crsr.execute('create table SheetOne (Header1 text, Header2 text, Header3 text, Header4 text, Header5 text)')

        sql = "INSERT INTO SheetOne (Header1, Header2 ,Header3, Header4, Header5) values (?,?,?,?,?)"

        data = (1, 2, 3, 4, 5)
        crsr.execute(sql, data)  # write the first row of data
        crsr.execute(sql, (6, 7, 8, 9, 10))  # another row of data
conn.close()
print(('Created spreadsheet=%s worksheet=%s' % (filename, 'SheetOne')))
