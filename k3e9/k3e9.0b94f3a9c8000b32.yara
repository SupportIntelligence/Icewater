import "hash"

rule k3e9_0b94f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b94f3a9c8000b32"
     cluster="k3e9.0b94f3a9c8000b32"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor razy injector"
     md5_hashes="['a2e38bcfa0b3f6db7a92517a0b593967', 'a2e38bcfa0b3f6db7a92517a0b593967', 'ad1f0a8655254c7ae46a07cc979671df']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

