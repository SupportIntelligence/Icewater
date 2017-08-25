import "hash"

rule k3e9_621c9899c2200b00
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.621c9899c2200b00"
     cluster="k3e9.621c9899c2200b00"
     cluster_size="62 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e930a9a3ce59db2d8ff75d22d6abca7b', 'beee85916bf320e5679851c3b51f4519', 'd169cdd38be6f56a20b40b9f14f40a9f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,256) == "ef96c463a0314afb568b9965012aec6e"
}

