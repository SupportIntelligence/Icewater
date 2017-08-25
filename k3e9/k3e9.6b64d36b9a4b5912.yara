import "hash"

rule k3e9_6b64d36b9a4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b9a4b5912"
     cluster="k3e9.6b64d36b9a4b5912"
     cluster_size="113 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['b994e6e6c26bd05a78b867e9556aff91', 'a31c254a7ae472143003115fd4927c19', 'aca4de23eb05c39b26f85e8dff5d39cf']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(23792,1036) == "663025776e46806a4b7c0489da905646"
}

