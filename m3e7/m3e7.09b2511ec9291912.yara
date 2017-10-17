import "hash"

rule m3e7_09b2511ec9291912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.09b2511ec9291912"
     cluster="m3e7.09b2511ec9291912"
     cluster_size="76 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="corruptfile dglq heuristic"
     md5_hashes="['eb6c8913ff04833b4df8b4306677842d', '9f12844954470bdd862d2bc30639c4c1', '438d6b2278e231627170a0f562c9120d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(32768,1024) == "eba47e751eba0d76140587d5c91d4ef1"
}

