# Certbot for Windows (beta)

The Certbot development team is proud to offer you the first beta release of Certbot for Windows.

This document explains how to install Certbot and use it on Windows.

Please note that this option is intended for the situation where your web server runs Windows. If you use Windows on your personal computer but have a web server with a different operating system, you should normally install Certbot on the web server (probably via SSH) instead of on your local computer. This document is not intended to describe that situation.

## Supported features

All usual operations to create and manage an account, manage existing certificates, or select the ACME server, are supported.

In terms of authenticator plugins, `standalone`, `manual` and `webroot` are supported. DNS plugins will be available soon.

For now, no installer plugins are available. `apache` and `nginx` will be available soon, and a new installer for IIS is under development. This means that you will obtain a PEM-formatted certificate and will have to import it into your web server application or keystore by yourself. This may also require you to convert the certificate from PEM format into a different format first.

Automated certificate renewals are supported.

All options available for a given supported command, as described by the documentation, will work in Certbot for Windows.

## Installation

The following operations need to be executed using an account with **administrative privileges** on the machine where you want to install Certbot.

Certbot can be installed through an installer that is available:
- on GitHub: go to the Certbot GitHub release (https://github.com/certbot/certbot/releases), select the last version of Certbot (v0.40.0 currently), and download the installer named `certbot-beta-installer-win32.exe in the assets.
- on Certbot's official website: _[specific URL and procedure to be defined]_

The Certbot development team can guarantee the authenticity of the Windows installer only for these two sources as of now. Be cautious in downloading Windows installers from other sources, because they could be corrupt or include malicious functionality.

Once downloaded, double-click on the installer to run it. You will need to select the location for Certbot installation directory, or keep the default one (`C:\Program Files(x86)\Certbot).

At this point Certbot is ready to run.

## Using Certbot

Certbot is a command line interface with no graphical UI. To interact with it you will need a command line: the classic one (`cmd.exe`) and PowerShell are both supported. You can also use Bash for Windows (available if you installed Git for Windows for instance) if you prefer.

The command line needs to be executed with **administrative privileges**. Otherwise Certbot will fail to run.

Once the command line is opened, simply run the following command to get the Certbot help:
```
certbot --help
```

Indeed the Certbot installer set up the `PATH` to expose the command line interface `certbot`. So you can run it from any folder, or even include it in your scripts.

With respect to the supported features as described in the _Supported features_ section, you can check the inline help or https://certbot.eff.org/docs/ to check how to use a specific feature in Certbot.

## Configuration

Certbot's functions are based around a configuration folder, where all the configuration files and generated certificates are available.

On Windows, this folder is `C:\Certbot`. This can be changed using the `--config-dir` flag on the Certbot CLI.

Within this folder you will find the following folders:
* `C:\Certbot\live`: contains current versions of issued certificates and keys
* `C:\Certbot\archive`: contains all current and previous versions of issued certificates and keys
* `C:\Certificate\logs`: contains Certbot activity logs

Doing backups of `C:\Certbot` folder is all that's required to save your Certbot installation. Please note that the `archive` folder is sensitive because it contains cryptographic private keys: this folder should not be disclosed to unauthorized parties.

## Certificate renewals

Renewals are supported by Certbot for Windows and are even already configured. Indeed the Certbot installer created a scheduled task during the installation to execute `certbot renew` twice a day.

All certificates created with Certbot for Windows are then automatically renewed out-of-the-box, provided that the required environment to renew is available (e.g. credentials, running web server ...). Indeed Certbot remembers the method that you used to prove your control over the domain name at the time you originally created each certificate. This method is also used for automated renewals. Therefore, if your environment has changed since you first obtained your certificate (for example, if TCP port 80 is no longer free), you might need to change the associated authentication method in order for automated renewals to continue working.

## A note on manual hooks

As explained by the [manual plugin documentation](https://certbot.eff.org/docs/using.html#manual), you may need to set up authentication and cleanup hooks to make the `manual` plugin work as expected, in particular with `DNS-01` challenges.

Similarly to Linux, Certbot for Windows supports any file executable for this platform, if it is available in the `PATH`. It can be `.bat`, `.ps1` or even executable binaries like `.exe`.

## A note on files security

Assets generated by Certbot, in particular keys, are critical in terms of security and should never be exposed to unauthorized accesses. Certbot for Windows leverages DACLs implemented by the NTFS filesystem to enforce this control: keys and sensitive materials are readable by default only by the account that runs Certbot, the `Administrators` group and `SYSTEM`.

## Updating Certbot

When a new version of Certbot release is available, please download the new installer for this new version as described in the _Installation_ section, and run it. The installer will update your existing installation of Certbot.

## Getting help, reporting issues, asking for new features

If you encounter some difficulties to install or use Certbot for Windows, there is a dedicated area in the Let's Encrypt Community Forum that can be reached at _[URL to dedicated category on Certbot (beta) for Windows in the Let's Encrypt Community Forum to be defined]_.

If you find an issue, or want to ask for a new feature on Certbot for Windows, do not hesitate to create a new issue in the [Certbot GitHub repository](https://github.com/certbot/certbot/issues). When filing an issue, you can tag it with the `area: windows` tag to ensure that the developers see that it relates to Certbot on Windows. Also please do not forget that some existing features for Linux systems are not yet available on Windows, but are planned to be added (see the section _Supported features_).