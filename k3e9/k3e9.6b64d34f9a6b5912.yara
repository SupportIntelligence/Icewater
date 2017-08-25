import "hash"

rule k3e9_6b64d34f9a6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f9a6b5912"
     cluster="k3e9.6b64d34f9a6b5912"
     cluster_size="259 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['c071ab000529abd1f66c51e5e1317b7d', 'a3da3e764db760bb0d858f9a26f32422', 'c2765e4c63aa7bf8d463267603fa06b5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8252,1036) == "bf35bc45826b9aa0cee18bd0fde1c00c"
}

