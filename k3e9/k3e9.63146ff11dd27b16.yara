import "hash"

rule k3e9_63146ff11dd27b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ff11dd27b16"
     cluster="k3e9.63146ff11dd27b16"
     cluster_size="182 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d8e203d54c40b2f38277c7b2d925bfe6', '173d63b0634aac16eeb0eba26e4f3d54', 'abc805b03e6fb658f5d4d8c2709cf618']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29184,256) == "2e1e953ff8b0c4afd8a93f50be9aa1f2"
}

