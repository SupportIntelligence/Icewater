import "hash"

rule k3e9_091cf3e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.091cf3e9c8000b32"
     cluster="k3e9.091cf3e9c8000b32"
     cluster_size="223 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['f68d4f191d3ae8538509f9cc5feabe67', 'd1e3d8be8b8ebe40d6227c74e29a4619', 'd003d62e135e01a0de6756a03b1ffae4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

