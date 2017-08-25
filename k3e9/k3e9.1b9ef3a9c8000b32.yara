import "hash"

rule k3e9_1b9ef3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b9ef3a9c8000b32"
     cluster="k3e9.1b9ef3a9c8000b32"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy backdoor injector"
     md5_hashes="['3830f512b5186d2240828b17d788f4e9', 'ca39bc61b896c6cdd2f3cdde303438d1', '3830f512b5186d2240828b17d788f4e9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26880,256) == "769fc8de8f491831149e0e56b6e57744"
}

