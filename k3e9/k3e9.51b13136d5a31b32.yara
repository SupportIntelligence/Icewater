import "hash"

rule k3e9_51b13136d5a31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13136d5a31b32"
     cluster="k3e9.51b13136d5a31b32"
     cluster_size="128 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c62c804acfb06b287dd820d9339bfd34', '830f64ff3e8b9df024c12c7adb05f36d', 'c5c9937afbe4a965b622680e15fb0e05']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

