import "hash"

rule m3e9_432c2d4b4944efa5
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.432c2d4b4944efa5"
     cluster="m3e9.432c2d4b4944efa5"
     cluster_size="311 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['9fabc55c8e07e58de4a1cfd1ce09449a', '85388ffe766ca802880710b8f59249c2', '2d53be16930c6df553b7649e54f6ca11']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(147456,1536) == "2e29634a2b82ffac3840a31d88a9e065"
}

