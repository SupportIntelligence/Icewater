import "hash"

rule k3e9_63146ff11dd27b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ff11dd27b16"
     cluster="k3e9.63146ff11dd27b16"
     cluster_size="203 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d1148f3c909b32b4e4164c7f6a41c13e', 'c73ee1021e0e5fb77ad76757713e95e2', 'c92f254c1e2af6eb0a557ceb77da92aa']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

