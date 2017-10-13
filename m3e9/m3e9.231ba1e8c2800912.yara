import "hash"

rule m3e9_231ba1e8c2800912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.231ba1e8c2800912"
     cluster="m3e9.231ba1e8c2800912"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['db5ae94625e7b67adaf22882673aa55d', 'd3cd229dbe5ebd5014147f8f710238ad', 'c8f638fe2c929314faa9b1a5dfc8d26a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(56320,1024) == "ef3bfa08a1e4c28928df02bba0a783b9"
}

