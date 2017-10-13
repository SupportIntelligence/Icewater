import "hash"

rule m3e9_499adb5cd8bb0b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.499adb5cd8bb0b32"
     cluster="m3e9.499adb5cd8bb0b32"
     cluster_size="829 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="symmi dorkbot jorik"
     md5_hashes="['450e6de10c1002f633311ab3a74daa3c', '956b7a4a8707b163e0abbaddd22de713', 'a602c163e8359506df94e9d9a2b5a608']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(148912,1027) == "04d924fc3bfde7b4f63b641a9b34de96"
}

