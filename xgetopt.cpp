// from http://yellosoft.svn.beanstalkapp.com/apps/IOS7Crypt/
// Note: made some changes so it compiles with cl.exe

// XGetopt.cpp  Version 1.2
//
// Author:  Hans Dietrich
//          hdietrich2@hotmail.com
//
// Description:
//     XGetopt.cpp implements getopt(), a function to parse command lines.
//
// History
//     Version 1.2 - 2003 May 17
//     - Added Unicode support
//
//     Version 1.1 - 2002 March 10
//     - Added example to XGetopt.cpp module header
//
// This software is released into the public domain.
// You are free to use it in any way you like.
//
// This software is provided "as is" with no expressed
// or implied warranty.  I accept no liability for any
// damage or loss of business that this software may cause.
//
///////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

///////////////////////////////////////////////////////////////////////////////
//
//  X G e t o p t . c p p
//
//
//  NAME
//       getopt -- parse command line options
//
//  SYNOPSIS
//       int getopt(int argc, char *argv[], char *optstring)
//
//       extern char *optarg;
//       extern int optind;
//
//  DESCRIPTION
//       The getopt() function parses the command line arguments. Its
//       arguments argc and argv are the argument count and array as
//       passed into the application on program invocation.  In the case
//       of Visual C++ programs, argc and argv are available via the
//       variables __argc and __argv (double underscores), respectively.
//       getopt returns the next option letter in argv that matches a
//       letter in optstring.  (Note:  Unicode programs should use
//       __targv instead of __argv.  Also, all character and string
//       literals should be enclosed in _T( ) ).
//
//       optstring is a string of recognized option letters;  if a letter
//       is followed by a colon, the option is expected to have an argument
//       that may or may not be separated from it by white space.  optarg
//       is set to point to the start of the option argument on return from
//       getopt.
//
//       Option letters may be combined, e.g., "-ab" is equivalent to
//       "-a -b".  Option letters are case sensitive.
//
//       getopt places in the external variable optind the argv index
//       of the next argument to be processed.  optind is initialized
//       to 0 before the first call to getopt.
//
//       When all options have been processed (i.e., up to the first
//       non-option argument), getopt returns EOF, optarg will point
//       to the argument, and optind will be set to the argv index of
//       the argument.  If there are no non-option arguments, optarg
//       will be set to NULL.
//
//       The special option "--" may be used to delimit the end of the
//       options;  EOF will be returned, and "--" (and everything after it)
//       will be skipped.
//
//  RETURN VALUE
//       For option letters contained in the string optstring, getopt
//       will return the option letter.  getopt returns a question mark (?)
//       when it encounters an option letter not included in optstring.
//       EOF is returned when processing is finished.
//
//  BUGS
//       1)  Long options are not supported.
//       2)  The GNU double-colon extension is not supported.
//       3)  The environment variable POSIXLY_CORRECT is not supported.
//       4)  The + syntax is not supported.
//       5)  The automatic permutation of arguments is not supported.
//       6)  This implementation of getopt() returns EOF if an error is
//           encountered, instead of -1 as the latest standard requires.
//
//  EXAMPLE
//       BOOL CMyApp::ProcessCommandLine(int argc, char *argv[]) {
//           int c;
//
//           while ((c = getopt(argc, argv, _T("aBn:"))) != EOF) {
//               switch (c) {
//                   case _T('a'):
//                       TRACE(_T("option a\n"));
//                       //
//                       // set some flag here
//                       //
//                       break;
//
//                   case _T('B'):
//                       TRACE( _T("option B\n"));
//                       //
//                       // set some other flag here
//                       //
//                       break;
//
//                   case _T('n'):
//                       TRACE(_T("option n: value=%d\n"), atoi(optarg));
//                       //
//                       // do something with value here
//                       //
//                       break;
//
//                   case _T('?'):
//                       TRACE(_T("ERROR: illegal option %s\n"), argv[optind-1]);
//                       return FALSE;
//                       break;
//
//                   default:
//                       TRACE(_T("WARNING: no handler for option %c\n"), c);
//                       return FALSE;
//                       break;
//               }
//           }
//           //
//           // check for non-option args here
//           //
//           return TRUE;
//       }
//
///////////////////////////////////////////////////////////////////////////////

wchar_t * optargW = NULL;  // global argument pointer
char * optarg = NULL;      // global argument pointer
int    optind = 0;         // global argv index

int getopt(int argc, char * argv[], char * optstring)
{
  static char * next = NULL;
  char c;
  char * cp = NULL;
  
  if (optind == 0) next = NULL;
  optarg = NULL;

  if (!next || *next == 0) {
    if (optind == 0) optind++;
    
    if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == 0) {
      optarg = NULL;
      if (optind < argc)
        optarg = argv[optind];
      return EOF;
    }
    if (argv[optind][0] == '-' && argv[optind][1] == '-') {
      optind++;
      optarg = NULL;
      if (optind < argc)
        optarg = argv[optind];
      return EOF;
    }
    next = argv[optind];
    next++;        // skip past -
    optind++;
  }
  c = *next++;
  cp = strchr(optstring, c);
  if (!cp || c == ':') return '?';
  cp++;

  if (*cp != ':')
    return c;

  if (*next != 0) {
    optarg = next;
    next = NULL;
    return c;
  }
  if (optind < argc) {
    optarg = argv[optind];
    optind++;
    return c;
  }
  return '?';
}

int getoptW(int argc, wchar_t * argv[], char * optstring)
{
  static wchar_t * next = NULL;
  wchar_t c;
  char * cp = NULL;

  if (optind == 0) next = NULL;
  optargW = NULL;

  if (!next || *next == 0) {
    if (optind == 0) optind++;

    if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == 0) {
      optargW = NULL;
      if (optind < argc)
        optargW = argv[optind];
      return EOF;
    }
    if (argv[optind][0] == '-' && argv[optind][1] == '-') {
      optind++;
      optargW = NULL;
      if (optind < argc)
        optargW = argv[optind];
      return EOF;
    }
    next = argv[optind];
    next++;        // skip past -
    optind++;
  }

  c = *next++;
  if (c == ':')
    return '?';    // incorrect param name
  
  cp = strchr(optstring, c);
  if (!cp)
    return '?';    // param name not supported

  cp++;
  if (*cp != ':')
    return c;        // param without value

  if (*next != 0) {  // param and value docked !!!
    optargW = next;
    next = NULL;
    return c;
  }
  if (optind < argc) {
    optargW = argv[optind];
    optind++;
    return c;
  }
  return '?';
}

#ifdef MAX_PARAM_LEN
#undef MAX_PARAM_LEN
#endif
#define MAX_PARAM_LEN 4

int getoptEx(int argc, char * argv[], ...)
{
  char * optstring;
  char * xp;
  char c;
  int pos;
  char par[8];
  size_t plen;
  size_t i;
  unsigned int x;
  va_list argptr;

  if (optind == 0) optind++;
  optarg = NULL;

  {
    if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == 0) {
      optarg = NULL;
      if (optind < argc)
        optarg = argv[optind];
      return EOF;
    }
    if (argv[optind][0] == '-' && argv[optind][1] == '-') {
      optind++;
      optarg = NULL;
      if (optind < argc)
        optarg = argv[optind];
      return EOF;
    }
    xp = argv[optind];
    xp++;        // skip past -
    optind++;
  }

  x = 0;
  plen = 0;
  for (i = 0; i < MAX_PARAM_LEN; i++) {
    c = (char)xp[i];
    if (c == 0)
      break;
    if (c == ':')
      return '?';     // incorrect param name
    par[plen++] = c;
    x <<= 8;
    x += (unsigned int)c;
  }
  par[plen] = 0;

  va_start(argptr, argv);
  c = 0;
  while ((optstring = va_arg(argptr, char *)) != NULL) {
    pos = strncmp(optstring, par, plen);
    if (pos == 0 && optstring[plen] == 0) {
      c = 1;
      break;
    }
    if (pos == 0 && optstring[plen] == ':') {
      c = 2;
      break;
    }
  }
  va_end(argptr);

  if (c == 0)
    return '?';     // param name not supported

  if (c == 1)
    return x;       // param without value

  if (optind < argc) {
    optarg = argv[optind];
    optind++;
    return x;
  }
  return '?';
}

int getoptExW(int argc, wchar_t * argv[], ...)
{
  char * optstring;
  wchar_t * xp;
  char c;
  int pos;
  char par[8];
  size_t plen;
  size_t i;
  unsigned int x;
  va_list argptr;

  if (optind == 0) optind++;
  optargW = NULL;

  {
    if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == 0) {
      optargW = NULL;
      if (optind < argc)
        optargW = argv[optind];
      return EOF;
    }
    if (argv[optind][0] == '-' && argv[optind][1] == '-') {
      optind++;
      optargW = NULL;
      if (optind < argc)
        optargW = argv[optind];
      return EOF;
    }
    xp = argv[optind];
    xp++;        // skip past -
    optind++;
  }

  x = 0;
  plen = 0;
  for (i = 0; i < MAX_PARAM_LEN; i++) {
    c = (char)xp[i];
    if (c == 0)
      break;
    if (c == ':')
      return '?';     // incorrect param name
    par[plen++] = c;
    x <<= 8;
    x += (unsigned int)c;
  }
  par[plen] = 0;

  va_start(argptr, argv);
  c = 0;
  while ((optstring = va_arg(argptr, char *)) != NULL) {
    pos = strncmp(optstring, par, plen);
    if (pos == 0 && optstring[plen] == 0) {
      c = 1;
      break;
    }
    if (pos == 0 && optstring[plen] == ':') {
      c = 2;
      break;
    }
  }
  va_end(argptr);

  if (c == 0)
    return '?';     // param name not supported

  if (c == 1)
    return x;       // param without value

  if (optind < argc) {
    optargW = argv[optind];
    optind++;
    return x;
  }
  return '?';
}

