import "hash"

rule o3e9_3b1b4a84ca210912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.3b1b4a84ca210912"
     cluster="o3e9.3b1b4a84ca210912"
     cluster_size="58 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kazy unwanted bmmedia"
     md5_hashes="['abdc63e949d569af041ee7a93e960447', '90d59a4f409ea0b88f4b109161fce85c', '50b064ca4fc33dcdb7139c5570a5648c']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(192512,1024) == "e7c605a42191e3e2ab0aad2a4eec9583"
}

