import "hash"

rule k3e9_51b131369da31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b131369da31b32"
     cluster="k3e9.51b131369da31b32"
     cluster_size="44 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['86f7c5aa5afb4c5797f96abc145ab2f5', 'c0362957ce1eb77a72ed138002ac898d', 'ce8a11a27d811f994f2751603e7cc503']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

