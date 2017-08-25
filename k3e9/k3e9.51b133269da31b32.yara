import "hash"

rule k3e9_51b133269da31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b133269da31b32"
     cluster="k3e9.51b133269da31b32"
     cluster_size="211 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b1fa49f76e86bba5e9ccb88667effcbd', 'e7c67e4b2cff5e97192c8f7c52fd05c5', 'e7580567caaab71357263ca1c1c232e6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

