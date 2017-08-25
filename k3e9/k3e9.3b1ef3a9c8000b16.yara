import "hash"

rule k3e9_3b1ef3a9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b1ef3a9c8000b16"
     cluster="k3e9.3b1ef3a9c8000b16"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="backdoor razy injector"
     md5_hashes="['d0ca43c18742b6dfbcf72b57539e6085', 'a61e0636bb6a51e64388cd6a9a3c4c73', 'd93094df7699d760bc7ed8ecd24a738b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

