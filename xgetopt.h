#ifndef _XGETOPT_H_
#define _XGETOPT_H_

extern wchar_t * optargW;
extern char * optarg;
extern int optind;

int getopt(int argc, char * argv[], char * optstring);
int getoptW(int argc, wchar_t * argv[], char * optstring);

int getoptEx(int argc, char * argv[], ...);
int getoptExW(int argc, wchar_t * argv[], ...);

#endif /* _XGETOPT_H_ */