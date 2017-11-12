import "hash"

rule m3e9_691f97a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691f97a1c2000912"
     cluster="m3e9.691f97a1c2000912"
     cluster_size="6926 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['1dd37519970d0e7f436a55c0ce884d9e', '1ac2419f08e608e103bddc9731544227', '292c6b8a9b76b2523c5c4e22440b3c05']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(13312,1024) == "6fcbed2d950ec37b7bd25ef8cef06ab5"
}

