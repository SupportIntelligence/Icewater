import "hash"

rule o3e9_139256e9ca800932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.139256e9ca800932"
     cluster="o3e9.139256e9ca800932"
     cluster_size="370 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="heuristic itorrent loadmoney"
     md5_hashes="['151b54c3d6958eee2253ddbf72959d88', '045023059f94edf9edd7948b62b76dab', '1326ce6550ff605b3c876584e0d64dd0']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(469574,1029) == "7797793853cf66db2f1a61922088db30"
}

