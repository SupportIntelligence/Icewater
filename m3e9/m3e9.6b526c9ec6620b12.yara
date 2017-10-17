import "hash"

rule m3e9_6b526c9ec6620b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b526c9ec6620b12"
     cluster="m3e9.6b526c9ec6620b12"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['41d99f9280b8277c76212f3a098c3375', 'be293c8490c5829a6a2edc83abbc4dbd', '73a9a4aac97e5cc4eb52b99dfe0e59ad']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(100352,1024) == "a5eeb8d6bc95039249c062e1bfa20c8f"
}

