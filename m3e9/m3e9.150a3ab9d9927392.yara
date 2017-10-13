import "hash"

rule m3e9_150a3ab9d9927392
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.150a3ab9d9927392"
     cluster="m3e9.150a3ab9d9927392"
     cluster_size="267 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['26ecd1bb813aba0e2c08b9a7bfadeb92', '7e19af997378cee5d5832bce17ca7f31', '26b8031e05c0f2a6985ffdd85c634f39']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(108544,1071) == "698123b4097303620115637265df5a66"
}

