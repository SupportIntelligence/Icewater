import "hash"

rule n3e9_2b1632a2d7bb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b1632a2d7bb1912"
     cluster="n3e9.2b1632a2d7bb1912"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="fvyj kryptik malicious"
     md5_hashes="['913889d445a37ab62abe613f6f5cf3ea', '1d67b7133cb4259d3f7fd03a1ae8f099', '2ae061d32a8345c4a144d410a928c1a6']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(709632,1024) == "20f13a0d0f631a8373af6a6e68af6e16"
}

