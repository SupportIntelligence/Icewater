import "hash"

rule k3e9_6b64d34b1a6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b1a6b5912"
     cluster="k3e9.6b64d34b1a6b5912"
     cluster_size="160 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['df17a5a38681eaf02eb28d8085824d37', 'b18e98ce1fbd493bc517513d0f3f8b3d', '81ef48088254d0aa443c414f92d5b61e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(14468,1036) == "3fc9b6513c182f90d41c33f933010485"
}

