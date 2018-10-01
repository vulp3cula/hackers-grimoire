# Linux basics

## Finding things

There are some basic commands to find files and executables, but each one works differently.

### Locate

Search against an index which must be updated periodically:
```
updatedb
locate nc.exe
```
### Which
Search through directories defined in the `$PATH` environment variable:
```
which gcc
```
### Find
Search recursively through directories: 
```
find / -name cron*
```
