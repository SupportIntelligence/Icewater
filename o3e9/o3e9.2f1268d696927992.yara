import "hash"

rule o3e9_2f1268d696927992
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2f1268d696927992"
     cluster="o3e9.2f1268d696927992"
     cluster_size="1058 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['4348bc8228c0a98beac0d2a1c82c6757', '43db669668a164ea2fe3613e9f99422b', '01e35904a5711e2e6911022d5ebbd1b3']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1975103,1025) == "37d10d389ed73ed2c79dbaa2a65f9a89"
}

