import "hash"

rule m3e9_631c96cfc566f311
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631c96cfc566f311"
     cluster="m3e9.631c96cfc566f311"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple virut rahack"
     md5_hashes="['aafa677fe3beed607f60bd20bd853e0a', 'd9495c6b187050c2af07918b1a7d9557', 'aafa677fe3beed607f60bd20bd853e0a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(178688,1024) == "1596c37d7b83e8d61aec91f1f8c7700f"
}

