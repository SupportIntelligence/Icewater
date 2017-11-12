import "hash"

rule m3e9_53b6bb58dae31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.53b6bb58dae31912"
     cluster="m3e9.53b6bb58dae31912"
     cluster_size="859 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['866b2c3b41d0b337d744fa10fe6080ae', 'aca8e00fb95e07c36f6d1b49bc460c1a', 'a27a231f6bbf1bbf9c2b15664709b8c1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(80896,1280) == "c23266a7380bf3daa3a8422c6d2fd0c8"
}

