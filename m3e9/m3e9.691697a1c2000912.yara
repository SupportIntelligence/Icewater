import "hash"

rule m3e9_691697a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691697a1c2000912"
     cluster="m3e9.691697a1c2000912"
     cluster_size="2342 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['057935a20e1e99604c9bb582c481b86f', '74123cf64a6e4bd04551d453c85166fc', '0e4896a968ea0e83aabb6b19c0d639d6']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(13312,1024) == "6fcbed2d950ec37b7bd25ef8cef06ab5"
}

