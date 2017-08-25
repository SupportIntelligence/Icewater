import "hash"

rule k3e9_63146da119927b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da119927b16"
     cluster="k3e9.63146da119927b16"
     cluster_size="379 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['48d4701c3a09c8fdfd6261d5245b9bee', 'a624dfe36c4c8515c966c3e6c2f28fe4', 'c9327a60827382ae9d74fb21d5d161ce']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29184,256) == "2e1e953ff8b0c4afd8a93f50be9aa1f2"
}

