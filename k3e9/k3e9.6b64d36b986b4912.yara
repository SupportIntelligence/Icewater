import "hash"

rule k3e9_6b64d36b986b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b986b4912"
     cluster="k3e9.6b64d36b986b4912"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['b4a897aa504d74b6ea0e52d1b595951d', 'c43f154a0f4f22cdd93507caa436bf82', 'c01a36986c5f35f73c72366d7e2c4242']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17408,1024) == "9eb91dbb4265f33f83a408b75b887657"
}

