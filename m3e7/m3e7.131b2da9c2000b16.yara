import "hash"

rule m3e7_131b2da9c2000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.131b2da9c2000b16"
     cluster="m3e7.131b2da9c2000b16"
     cluster_size="298 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="slugin patched rgpjj"
     md5_hashes="['2f953d604cc27f07365d3d7b541c14c8', '698257a6787f6c7445fff70c48369b49', 'f3569412269c9bb28628a97251a4ba6d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(78848,1024) == "4bf9f4cf3a1d7dbfa0abf73197a724c1"
}

