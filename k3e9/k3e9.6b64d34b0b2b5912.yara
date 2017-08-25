import "hash"

rule k3e9_6b64d34b0b2b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b0b2b5912"
     cluster="k3e9.6b64d34b0b2b5912"
     cluster_size="24 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['73b204d00fe55bd6c4ff8c9297ca6276', 'cd3accdc0c56cdf56178319b59cf9d2f', 'a3039b7fe6f962818c6bb1e1bae1b2cf']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(23792,1036) == "663025776e46806a4b7c0489da905646"
}

