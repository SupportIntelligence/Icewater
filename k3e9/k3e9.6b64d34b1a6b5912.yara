import "hash"

rule k3e9_6b64d34b1a6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b1a6b5912"
     cluster="k3e9.6b64d34b1a6b5912"
     cluster_size="135 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['59ef8e70c30383e8dcc4a0485810ac5c', '10438b6769a404f05b68401a980272e5', 'aed1fb88e23fb2bd090d4a31ff11f955']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(14468,1036) == "3fc9b6513c182f90d41c33f933010485"
}

