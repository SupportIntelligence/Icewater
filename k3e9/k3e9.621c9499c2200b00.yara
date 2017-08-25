import "hash"

rule k3e9_621c9499c2200b00
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.621c9499c2200b00"
     cluster="k3e9.621c9499c2200b00"
     cluster_size="134 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['9ef589edfdef96ce9675ea33747ca5dc', 'bd9afff6d7f0427c91cc42b8bd1b0bb6', 'c98e93e4a314c4be3883704722349610']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,256) == "ef96c463a0314afb568b9965012aec6e"
}

