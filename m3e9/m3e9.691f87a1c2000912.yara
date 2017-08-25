import "hash"

rule m3e9_691f87a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691f87a1c2000912"
     cluster="m3e9.691f87a1c2000912"
     cluster_size="20 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bc91281d2d268e1d92cba1985e3f2354', 'c716c16bcc30ccd3b9e3a8a5d2c6e7d7', 'c401e12a2520d2dbb9f66692704b18bf']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(13312,1024) == "6fcbed2d950ec37b7bd25ef8cef06ab5"
}

