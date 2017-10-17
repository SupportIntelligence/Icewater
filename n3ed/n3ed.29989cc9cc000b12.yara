import "hash"

rule n3ed_29989cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.29989cc9cc000b12"
     cluster="n3ed.29989cc9cc000b12"
     cluster_size="32 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upack heuristic cryp"
     md5_hashes="['5946be0d7b30a7241370537a00d3a602', '012b484acfce03841e3380cc51c78842', '9a0db4bab364f56955c7e0fdf1949f38']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(323800,1026) == "71370d0accfb5b9efb291763cdd0515c"
}

