import "hash"

rule k3e9_3b18f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b18f3a9c8000b32"
     cluster="k3e9.3b18f3a9c8000b32"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor injector"
     md5_hashes="['b9e83c717e2f528aab8949a750462ea9', 'b9e83c717e2f528aab8949a750462ea9', 'bc83359ba1c0d1676e7e087ee40f9cfa']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

