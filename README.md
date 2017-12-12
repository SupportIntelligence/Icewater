# Project Icewater

This project provides open-source YARA rules for the detection of malware and malicious files. the anti-virus 
industry prefers names for a threat. This is my attempt to publish signatures as numbers. Since I find the 
naming of threats to be confusing and misleading I am attempting to locate threats in a phase-space so that 
their relationships can be measured, visualized and scientifically described.

Each YARA signature in this archive is organized by a prefix and a 64 bit integer. The prefix is an index into 
file size and file type while the suffix is a 64 bit coordinate in a multi dimensional hyper space. Within a prefix, 
edit distance may be used to understand how two clusters relate to each other.

# The Starting Problem
The basis of this research and this contribution to internet security is the idea of the Starting Problem which 
derives itself from Turing complete machines halting problem documented by Allen Turing in 1936. The staring problem 
I am defining thus: Knowing if a program should be allowed to run without running the program. My solution is to run 
about 4% of programs and by running them infer if the other 96% should be allowed to run.

Icewater is the project that clusters and sorts things on the interent. Icewater writes these rules in the hope that 
they are a compact form of transmitting knowledge regarding programs that should have their evil-bit set :) 

## How these rules get written
Icewater clusters malicious objects on the internet and when it has enough information about these objects it will publish 
a YARA rule that can be used to detect the threat. Since I am generally annoyed with the state of internet security I am
publishing many of the rules Icewater writes.

Each rule leverages the hash module of the YARA tools. I provide an offset into a file and the amount of data that you
should hash and the hash algorithm. I choose MD5 because it is fast and most folks dislike it because of the possibility 
of collision. If you think I should choose a different hashing algorithm please explain over beers.

## QA
Each rule is tested against the cluster that it is written from and against part of our larger data set. The rule should fire only for its cluster or a neighbor cluster that both have the same "family." Rules that pass these qualifications are published in this archive.  Rules that fail these tests are used to inform the process and debug the systems that generate the rules. If you find a rule that is missing its target please let me know, contact details are below.

## Is Icewater a form of Artifical Intelligence?
Yes, if you are a VC -- Icewater is based off a kind of mathematics that is used to describe the physical world, much like the 
math that we use for training AI. Icewater uses the same algorithms all Eukaryote (any cell that has a nucleus) use to organize their DNA. If you don't think binaries either in PE or COFF format are like DNA... Well, they are. You are a robot -- get used 
to it.

Remember Icewater writes the rules, I just write the part that writes Icewater, but I didn't write the 
algorithm -- nature did.

## Goals
My goal for this project is to place a large quantity of YARA rules into the network security community that it measurably
effects global cybersecurity. Please let me know when you think I'm getting close to my goal.

# License
Pay close attention to the RIL (Rick's Internet License) is is similar to the BSD with a 3rd clause that requires 
that if you use these rules and know me in physical space, you may need to acknowledge that you use these rules. I do 
enforce the license at public and private events. 

# Contact
webpage:  http://icewater.io  
blog:     http://cyberwarhead.com  
Twitter:  @wessorh  
