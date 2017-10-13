import "hash"

rule m3e9_691797a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691797a1c2000912"
     cluster="m3e9.691797a1c2000912"
     cluster_size="2087 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['574bf90ff7f8041ccb1207e655311c1b', '08cfc81a3869b40480506fdfd32bac16', '54a3c8281e1df338afb90f85f3c64be1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(13312,1024) == "6fcbed2d950ec37b7bd25ef8cef06ab5"
}

