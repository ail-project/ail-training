Here are some yare-tracker use-cases that one can find interesting to fiddle with:

1 - Finding drug stores 
`drugs.yar` is an example of yara rules one could use to find drugmarkets.

2 - Finding a vaccine 
`vax.yar` is an example of yara rules one could use to find vaccine offers.

3 - Finding information about an exploit

`apt_hafnium.yar` is a set of yara rules copied from
https://github.com/Neo23x0/signature-base/blob/master/yara/apt_hafnium.yar but
modified to keep only condition on strings that AIL can understand. Such a
ruleset usually yields exploit PoC code, technical writeups, victim data leaks,
and sometimes interesting forum discussions.
