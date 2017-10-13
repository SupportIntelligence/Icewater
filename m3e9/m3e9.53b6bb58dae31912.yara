import "hash"

rule m3e9_53b6bb58dae31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.53b6bb58dae31912"
     cluster="m3e9.53b6bb58dae31912"
     cluster_size="526 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b3ff48e256b4c71e59897dd0cb8eebc4', '8345da66d99033f0fe2495b8351f457d', '230884433bae200578fcd10762752108']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(80896,1280) == "c23266a7380bf3daa3a8422c6d2fd0c8"
}

