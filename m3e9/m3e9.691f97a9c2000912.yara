import "hash"

rule m3e9_691f97a9c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691f97a9c2000912"
     cluster="m3e9.691f97a9c2000912"
     cluster_size="2432 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['440b354688f60390033ce12018960166', '32efe372750da43cbf4cd62478ed1883', '2c2d5539f44ccfef01e96151915435ff']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(13312,1024) == "6fcbed2d950ec37b7bd25ef8cef06ab5"
}

