import "hash"

rule o3e9_1d924cc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1d924cc1cc000b32"
     cluster="o3e9.1d924cc1cc000b32"
     cluster_size="10377 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="strictor adstantinko advml"
     md5_hashes="['0451a194566247af7f3294a9257fc3b7', '036139ca4292605670679078f780f339', '0068c667c32c727295993595d7b23ccf']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1182720,1024) == "1121c55ecb9cf9f11fc99e44a015a7be"
}

