import "hash"

rule n3e9_1b18e5a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b18e5a1c2000b32"
     cluster="n3e9.1b18e5a1c2000b32"
     cluster_size="703 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple virut rahack"
     md5_hashes="['1d5990b902d01e99d4ebd70d6ce3352b', 'ae6d855ec0b2c2172e2cdb979b5033e1', 'a3ce6be72b6b743a3c2f9894f9a34825']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(61952,1024) == "6a039dc6f36c112b920bef9b8a73cb0e"
}

