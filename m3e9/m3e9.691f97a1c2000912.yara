import "hash"

rule m3e9_691f97a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691f97a1c2000912"
     cluster="m3e9.691f97a1c2000912"
     cluster_size="5629 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['116f79353b71c2f24dddb1f21b515d0e', '04c215c994b843cec36d58dd01a7a456', '134752f7b84812ffa2a62bc9ab43d3cb']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(13312,1024) == "6fcbed2d950ec37b7bd25ef8cef06ab5"
}

