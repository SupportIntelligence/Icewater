import "hash"

rule k3e9_2b16f3e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b16f3e9c8000b32"
     cluster="k3e9.2b16f3e9c8000b32"
     cluster_size="138 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['ba8396dc7a825e7838c4dbda2801ff58', 'e9c7fa49ea77d7df4cf8d0571e7c28f2', 'c23bce53f6ec5616f7d92f7197f6041d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

