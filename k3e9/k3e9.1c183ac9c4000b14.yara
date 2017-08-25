import "hash"

rule k3e9_1c183ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1c183ac9c4000b14"
     cluster="k3e9.1c183ac9c4000b14"
     cluster_size="43 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['b423abd8dcb6ef2079abb70f4c7c6fec', 'ee6ba8fedb6d6ad13c0d6a8d2424b8dd', 'c4c890242e4b0c4ff6a39bd3dcf3a37c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6400,256) == "1371fd7f3206a21874fbe56ff62fb073"
}

