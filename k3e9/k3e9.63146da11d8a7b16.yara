import "hash"

rule k3e9_63146da11d8a7b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da11d8a7b16"
     cluster="k3e9.63146da11d8a7b16"
     cluster_size="551 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a99ab0c30c71f6353ae993f66fe7657c', 'b04b13e69e0eba9fd7db7abed47233d0', '4f83ef16ffeb12a56fbdf24e2aa1c340']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

