import "hash"

rule k3e9_211c97c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.211c97c9cc000b16"
     cluster="k3e9.211c97c9cc000b16"
     cluster_size="251 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c39d3a1a2b581d58d5334559090c5694', 'da63b25b2e4ed710c98b60a7a35f68ab', 'b8dc6302bcb9ed0832b280aa354e4762']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(2560,256) == "05799272f4ea80317683ed87a673fd04"
}

