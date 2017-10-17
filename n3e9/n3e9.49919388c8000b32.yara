import "hash"

rule n3e9_49919388c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.49919388c8000b32"
     cluster="n3e9.49919388c8000b32"
     cluster_size="51 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious filerepmalware engine"
     md5_hashes="['24d5a1dcfe3cac920af6493ba816849e', 'd0d39e79937230904abab7dc840ab7a7', '4e1abea73e1ea73cb9eef8dc880ff4c5']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(190464,1024) == "9f66813552b88b85d0105cb4a79e42a2"
}

