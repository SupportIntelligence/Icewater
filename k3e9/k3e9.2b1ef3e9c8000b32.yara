import "hash"

rule k3e9_2b1ef3e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b1ef3e9c8000b32"
     cluster="k3e9.2b1ef3e9c8000b32"
     cluster_size="162 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['f3855f2a67dde58aa547f6bcad45cec6', 'd66d9227eca121c2eabb10787d8fd849', 'b0ddf4fd59757da1ee945f4c6c5943a5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

