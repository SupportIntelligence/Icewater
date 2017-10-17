import "hash"

rule n3ec_5e4f3299d2bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.5e4f3299d2bb0b12"
     cluster="n3ec.5e4f3299d2bb0b12"
     cluster_size="69 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious heuristic attribute"
     md5_hashes="['c388f688ef5ff7ac9752a879476b70d1', '45741a6f62d957cc7a0b0ef28bc13adb', '537457c8384c6fb29b1fd3b8adeb3fd0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(116224,1024) == "159ccb2670c4f08d98c394bed9aa6159"
}

