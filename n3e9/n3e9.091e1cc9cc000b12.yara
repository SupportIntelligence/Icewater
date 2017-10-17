import "hash"

rule n3e9_091e1cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.091e1cc9cc000b12"
     cluster="n3e9.091e1cc9cc000b12"
     cluster_size="57 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="softonic softonicdownloader unwanted"
     md5_hashes="['0ea766e01d5bf08494d9d5d1a39201f7', '0485a60e36b0a3f040da64e17417a025', '88854ce3acb0938dce973972364dc385']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(326656,1024) == "82040f3244ed0cf6c27b9a73ee6b3539"
}

