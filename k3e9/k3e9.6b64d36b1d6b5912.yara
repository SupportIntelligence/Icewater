import "hash"

rule k3e9_6b64d36b1d6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b1d6b5912"
     cluster="k3e9.6b64d36b1d6b5912"
     cluster_size="10 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['a6f6c0dd75cfed484a8d4c94ee82af70', 'b85fed5e709bcbcb95a2b1219715a136', 'a6f6c0dd75cfed484a8d4c94ee82af70']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(14468,1036) == "3fc9b6513c182f90d41c33f933010485"
}

