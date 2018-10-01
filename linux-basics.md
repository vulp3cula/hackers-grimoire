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
## Basic Bash scripting

### Filtering
Being able to process text-based files and pull out useful data is a useful skill. For example, to filter out domain names from an HTML file full of other stuff, you can `grep` for something uniquely associated with URLs, then cut out extraneous information:

```
<li><a href="http://newsroom.cisco.com/">Newsroom</a></li> # links you'd find in HTML
grep "href=" file.html | cut -d "/" -f 3
```
In the above example, we are grepping for `href=` which identifies hyperlinks in HTML. We can filter more precisely by looking for recurring characters that help us divide the data into smaller chunks. The command `cut -d "/"` chunks the data and separates it by `/`. The `-f 3` option tells us to filter out the 3rd chunk (field) of data. 

### Sort
Find unique items in a list with duplicates using `sort -u`:
```
grep "href=" file.html | cut -d "/" -f 3 | sort -u
```

### Simple loop
Run the `host` command on every domain in a text file:
```
for url in $(cat list.txt); do host $url; done
```
Grep the output of `host` to find successful lookups:
```
for url in $(cat list.txt); do host $url; done | grep "has address" | cut -d " " -f 4 | sort -u
```
In the above example, you're looking for lines with `has address`, filtering out the URL by using spaces as the delimiter and then removing duplicates with `sort`. 
