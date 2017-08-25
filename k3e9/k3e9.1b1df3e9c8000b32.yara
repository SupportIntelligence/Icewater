import "hash"

rule k3e9_1b1df3e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1df3e9c8000b32"
     cluster="k3e9.1b1df3e9c8000b32"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['56a500cd65fde34969fd6ad63a2de22e', 'e521c0ed84a240a5c51bb9fcb8f6c166', 'e521c0ed84a240a5c51bb9fcb8f6c166']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

