import "hash"

rule k3e9_139da164ddcb9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164ddcb9932"
     cluster="k3e9.139da164ddcb9932"
     cluster_size="295 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ed2d9b61dc1b4b90a40a6ae2e492e655', 'feb77797ed67c4c8c01529c4e43721b1', 'a87bc15bc4c8744fb28d7813e4519b45']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "10942184959ee54e3c7f95e54fa08bca"
}

