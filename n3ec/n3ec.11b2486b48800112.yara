import "hash"

rule n3ec_11b2486b48800112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11b2486b48800112"
     cluster="n3ec.11b2486b48800112"
     cluster_size="4117 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['472a972484f0a7f15d03aa969efa835e', '5f5adfe15cf7e84638c3c265a8812cc1', '3ae3c52cb838f81741c550b2f05a4f34']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(59632,1028) == "c1f1138f1d0ffda23d3da9e3fd56fa5a"
}

