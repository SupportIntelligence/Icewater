import "hash"

rule k3e9_6b64d34b9a6bd912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b9a6bd912"
     cluster="k3e9.6b64d34b9a6bd912"
     cluster_size="45 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['a395f66d0f5a49d3a6c5353fd6bb4730', 'dd6c0872e5b6f9fb38d4439f96e6ed50', 'a6a78b4c80c28b2b25fd6080a6852bf8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24828,1036) == "b430fb8cdfb0eaa02d3e9c2620da748a"
}

