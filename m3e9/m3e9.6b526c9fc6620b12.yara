import "hash"

rule m3e9_6b526c9fc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b526c9fc6620b12"
     cluster="m3e9.6b526c9fc6620b12"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a64d1ef7e02a045f1706ce3a8a2095c0', 'c2cd022ce5e30cc1f491a4dc05a7cd98', '947e9c1c8fdae2dd07fb1bba6fed2e23']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(100352,1024) == "a5eeb8d6bc95039249c062e1bfa20c8f"
}

