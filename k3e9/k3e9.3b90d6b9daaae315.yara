import "hash"

rule k3e9_3b90d6b9daaae315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b90d6b9daaae315"
     cluster="k3e9.3b90d6b9daaae315"
     cluster_size="27 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['a1397618dfdb609a74130e256c2289c1', 'd9c8ae43e2ecf7eb7332e49982c7491d', 'a1397618dfdb609a74130e256c2289c1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(23552,1024) == "213b8a7d51145a3ee8e0dd5665a75e6b"
}

