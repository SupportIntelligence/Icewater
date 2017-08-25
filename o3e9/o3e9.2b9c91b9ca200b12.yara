import "hash"

rule o3e9_2b9c91b9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2b9c91b9ca200b12"
     cluster="o3e9.2b9c91b9ca200b12"
     cluster_size="1086 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="kelios filetour bogent"
     md5_hashes="['01df3e592ace5a17e2fdb924858e131b', '0fb2fbe471b33c7d7e7926c9bfd16faa', '1b40137e47e3cc043170de86a0b53de8']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(674304,1024) == "30e2e6c7712dcd3a63b6d36c5e924376"
}

