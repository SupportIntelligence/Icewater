import "hash"

rule k3e9_6b64d34e8a6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34e8a6b5912"
     cluster="k3e9.6b64d34e8a6b5912"
     cluster_size="16 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['bd74a8ce27f854e459ff1b529eb8268b', 'c4051b5c617f24dcaf30927286e1007e', 'a965d5d6fcac5eba64b5ad4b5610389d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24828,1036) == "b430fb8cdfb0eaa02d3e9c2620da748a"
}

