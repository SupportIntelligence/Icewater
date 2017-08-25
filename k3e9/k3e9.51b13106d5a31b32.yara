import "hash"

rule k3e9_51b13106d5a31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13106d5a31b32"
     cluster="k3e9.51b13106d5a31b32"
     cluster_size="120 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c156aac4f0dbf350152eeb7a2e88cd39', 'bc3f17f20804eac57a2bfa79b17a6426', 'b7fa98df17f02cfc212b6af81a7954d5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

