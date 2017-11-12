import "hash"

rule k3e9_53bb0ee948000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.53bb0ee948000932"
     cluster="k3e9.53bb0ee948000932"
     cluster_size="452 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre generickd bublik"
     md5_hashes="['ad05a23f34c4274d7cbfe715f659720c', 'b5dde648a39fb5a1098fb9c8108e2a3d', '3af88a460be7db78fa7ef54a01485808']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24474,1075) == "db101c17914d325ad68aae120eeece75"
}

