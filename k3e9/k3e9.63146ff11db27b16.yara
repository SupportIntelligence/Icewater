import "hash"

rule k3e9_63146ff11db27b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ff11db27b16"
     cluster="k3e9.63146ff11db27b16"
     cluster_size="83 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a40e2d0bedc1d7f085a94a82694065dd', 'c8c719fa6928e1d3ce399b0477f02a01', 'd294f0dd7abd91be5bcf0e4461cd9405']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

