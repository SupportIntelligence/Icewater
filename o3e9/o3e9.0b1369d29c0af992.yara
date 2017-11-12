import "hash"

rule o3e9_0b1369d29c0af992
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0b1369d29c0af992"
     cluster="o3e9.0b1369d29c0af992"
     cluster_size="3007 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonstr dlboost installmonster"
     md5_hashes="['09121a0e57a83de66dacee38973328ba', '094934061ab2aeecaa5d4137b11c59b7', '0969dec54a4d4a7a0c471a5b89d1d490']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1485312,1024) == "0f79a0cc25dc972d1fee0f3ff88af5f1"
}

