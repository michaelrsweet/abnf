# ABNF to REGEX Library

The ABNF to REGEX library is a pair of PHP functions that validate standard
ABNF (RFC 5234) input and generate POSIX and Perl-compatible regular
expressions for use in schema and applications.

I provide an online form front-end for these functions at:

    http://abnf.msweet.org/

The file "example.php" shows how to implement your own web form.


## Functions

### abnf_load(string)

This function parses the ABNF contained in the supplied string. On success, it
returns an array of rules that can be passed to the "abnf_regex" function.

FALSE is returned on failure, with the following global variables describing
the issue:

- "abnf_error" contains a string describing the issue.
- "abnf_errorline" contains the line number in the string where the issue occurred.
- "abnf_errorcol" contains the column number in the string where the issue occurred.

### abnf_regex(rules, rulename, mode = ABNF_INSENSITIVE)

This function generates a regular expression for the named rule. If the named
rule does not exist, an empty string is returned.

The "mode" parameter can be any of the following constants:

- ABNF_INSENSITIVE : Generates a case-insensitive regular expression.
- ABNF_SENSITIVE : Generates a case-sensitive regular expression.
- ABNF_LOWERCASE : Generates a case-sensitive regular expression with all string literals converted to uppercase.
- ABNF_UPPERCASE : Generates a case-sensitive regular expression with all string literals converted to lowercase.


## Legal Stuff

Copyright (c) 2013-2019 Michael R Sweet

This software is provided under the terms of the MIT license, which is provided
in the file "LICENSE.md".

