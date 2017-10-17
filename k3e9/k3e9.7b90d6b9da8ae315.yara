import "hash"

rule k3e9_7b90d6b9da8ae315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.7b90d6b9da8ae315"
     cluster="k3e9.7b90d6b9da8ae315"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['d7a01d0ecb9957a8711eb2f22bbe312a', '0109834530d8e982f2f5232b891c83a3', 'cc52e130076e0d92a6cfd54d4791db78']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(14336,1024) == "ea6edfd2f8b00ea802d0c1920b2555fd"
}

