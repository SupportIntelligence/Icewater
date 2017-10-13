import "hash"

rule m3e9_391e6dc8c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.391e6dc8c4000b32"
     cluster="m3e9.391e6dc8c4000b32"
     cluster_size="2735 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zusy tinba backdoor"
     md5_hashes="['25f105022f97d2af234075935bc7f492', '01711c932cf34bb94048aac03394508e', '2beb7a795b19f123e51117a1bfd30739']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(98304,1024) == "8b6d178fb87a7de9fe6210f6d2ebc8bf"
}

