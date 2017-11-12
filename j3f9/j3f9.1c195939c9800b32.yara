import "hash"

rule j3f9_1c195939c9800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f9.1c195939c9800b32"
     cluster="j3f9.1c195939c9800b32"
     cluster_size="20013 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bdmj memscan flooder"
     md5_hashes="['09f0fc2fd26be08466b22d33cb1cd064', '0b5f1c674c2434c5d15e71b9ba8b5b29', '05e36b5cb7a790f50d50b5827fb5df55']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(5632,1536) == "58919d167d0df91f49e63bc7fc5bd2ba"
}

