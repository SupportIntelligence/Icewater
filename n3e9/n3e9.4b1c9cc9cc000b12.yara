import "hash"

rule n3e9_4b1c9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b1c9cc9cc000b12"
     cluster="n3e9.4b1c9cc9cc000b12"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="softonic softonicdownloader unwanted"
     md5_hashes="['cd16ba677855d8a3f1b9129558d1d4c2', '09a69339b7c367d9a45fde24d7922da5', '8c8720d0a436dff7d23259a10c4b7952']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(326656,1024) == "82040f3244ed0cf6c27b9a73ee6b3539"
}

