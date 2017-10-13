import "hash"

rule m3e9_13bb4b34d8bb9912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13bb4b34d8bb9912"
     cluster="m3e9.13bb4b34d8bb9912"
     cluster_size="149 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="lethic zbot shipup"
     md5_hashes="['ec7f54489930b08fc8d952fac5f9024f', '1e23c545b8f7c7c72b3243dcff29c55d', 'eaf6902459defa57ddd9948e819f3713']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(195072,1024) == "35fa0911c1dc9d1142d82b55893c4a5f"
}

