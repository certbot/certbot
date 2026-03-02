$ORIGIN sub.example.com.
$TTL 3600
sub.example.com.  IN  SOA   ns1.example.com. admin.example.com. ( 2020091025 7200 3600 1209600 3600 )

sub.example.com.  IN  NS    ns1
sub.example.com.  IN  NS    ns2

ns1           IN  A     192.0.2.2
ns2           IN  A     192.0.2.3
