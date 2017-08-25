import "hash"

rule k3e9_51b931169da31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b931169da31b32"
     cluster="k3e9.51b931169da31b32"
     cluster_size="66 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['be34840d93640e8d510bf087ccca48e1', '8466d9bc8b7c7c34b6efd99ab4046b01', 'df6d2aadc5c98e34693f4ce9efcb889f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,256) == "286a6db30376a984ee1706d41700b1f3"
}

