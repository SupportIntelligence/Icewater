import "hash"

rule k3e9_6b64f34b9b6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64f34b9b6b5912"
     cluster="k3e9.6b64f34b9b6b5912"
     cluster_size="27 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['a4785fc80bc748da69e5e64c9cfd39c0', '3c0fe75f498f676c43378e6615214b43', 'b64d770759f0d66f9d04f7419a8d5ac2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8252,1036) == "bf35bc45826b9aa0cee18bd0fde1c00c"
}

