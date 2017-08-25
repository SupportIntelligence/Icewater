import "hash"

rule m3e9_6b2d17a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2d17a9ca000b12"
     cluster="m3e9.6b2d17a9ca000b12"
     cluster_size="4757 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['139d4f5ef18281a0e44516f4e1a8c31a', '071d98a70e43dbe95e2853e1f0e6f6f9', '086f5ce07ac0ef336ad6fde450a63223']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(10240,1024) == "d6ce13b328d6c53dfb618f633f2323ac"
}

