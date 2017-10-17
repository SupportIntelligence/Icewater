import "hash"

rule m3e9_519bb60dc6620b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.519bb60dc6620b32"
     cluster="m3e9.519bb60dc6620b32"
     cluster_size="127 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['e9fe2062554562acdddb96300c2163d1', '9bfe263e060d92103661f1e0780b30cc', 'e472cd7e13d2899438cfe70cf3918972']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64000,1024) == "3a2b8b8e8c5ba0975f11e47f5b4896fd"
}

