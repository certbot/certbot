I believe this project is extremely important for the future of the Internet, and together, we can make it a success.  There is a ton of work to be done, so I thought I would compile a list of known issues or things I would like to see implemented.  If you would like to work on any of these sub-projects, I might suggest making an issue regarding it before you start the work. That way, everyone interested in the topic can convene and work together towards a solution in a group branch.  This list is by no means exhaustive. These ideas have just been floating around in my head for awhile, if you have ideas of your own, feel free to implement them.  All support is greatly appreciated!

Obligatory mailing list plug - Client software development can be discussed on this [mailing list]
(https://groups.google.com/a/letsencrypt.org/forum/#!forum/client-dev)

To subscribe without a Google account, send mail to
[client-dev+subscribe@letsencrypt.org]
(mailto:client-dev+subscribe@letsencrypt.org).

## Large Projects

#### NginxConfigurator

There has been alot of stated demand for nginx support and there have been a few interested developers.  It is an extremely popular webserver and I would really like to see it fully supported. (I may be biased because I run a few nginx servers myself :))  There is an Augeas lens for nginx.  I have already created a stub class based off an AugeasConfigurator. Hopefully the nginx supported lens will be sufficient, I personally haven't worked with it yet.  (Augeas is also a great open source project, so we could always perfect the lens as it will help both causes.)  Of course, you are free to find your own clean solution to supporting nginx though too.

#### Port to new OSes/distros

Would you like to see support in your area? We should setup a system to aid development and testing of other distributions.

## Medium to Large Sized Projects

#### NullWebserver Configurator

We would like to provide the ability for any system administrator running any webserver to at least retrieve a trusted certificate even if we can't do the installation for them.  This would require writing a new child of the configurator class that doesn't do any configuration, but can perform the generic challenges and receive a certificate.  For instance, for DVSNI, this would require that the client temporarily stop any webserver running on port 443. Spawn its own process that can handle the basic request and then restart the user's generic webserver once authentication is completed.  The output would simply be the chain, key, and certificate files in the cwd.  Notice: you only have to write a basic configurator class... everything else should be able to be reused.

## Medium Sized Projects

#### Challenge Support in ApacheConfigurator

Currently, the ApacheConfigurator class only fully supports DVSNI Challenges.  The TokenRecovery and RecoveryContact challenge files contain code that should be fairly accurate, but the challenge, and display code have both been refactored.  There is also a question of how you want to store such information. The recovery token is more of a proof of the previous transaction and could probably be stored on the computer or the user could input it from the command line if the appropriate token couldn't be found.  SimpleHTTPs would be an easy challenge to implement.  All of these of course require that the demo server will challenge you with them.  Currently, the demo server is only giving one challenge per domain.  The node-acme server should be extended.

#### Validator Class

It would be great to see all webserver configuration changes be validated.  Does the webserver deliver HTTPS at the example.com? Does HTTP traffic directed towards example.com:80 get redirected correctly to HTTPS on 443? OCSP Stapling? There is a stub class for this in the client directory already. 

#### Testing Framework

I would like to build a repository of valid configurations that we can test all changes to the code against before pushing the code into the master branch.  The ApacheConfigurator can be initialized with any SERVER_ROOT, so it should be feasible to automate the process and provide lots of tests.  This project could use the Validator class to verify correct results.

## Small Projects

#### Testing / Bug Fixes

This project hasn't been thoroughly tested yet for any system.  (See testing framework in medium projects) Do you have a strange setup that is in production? Any bug fixes to the code are always greatly appreciated. 

#### TODOs in code

There are a ton of TODOs listed in the code.  If you think you have a solution for any of them, feel free to submit a pull request.  Any help is greatly appreciated!