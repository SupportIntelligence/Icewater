import "hash"

rule k3e9_6b64d34b9b4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b9b4b5912"
     cluster="k3e9.6b64d34b9b4b5912"
     cluster_size="597 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['0f64b677d3b694395de74410bc291e1d', 'b833a1bbc6dc036a0363313d0c2db74e', 'a740d4759d4984f66d61c512ce3bf331']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(19648,1036) == "dbc5e24a5c7f08cf7d6715f88a9b1785"
}

