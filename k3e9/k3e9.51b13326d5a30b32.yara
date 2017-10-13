import "hash"

rule k3e9_51b13326d5a30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13326d5a30b32"
     cluster="k3e9.51b13326d5a30b32"
     cluster_size="172 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['9f039f5d9b8c4fed592e6da1c0ddeb4d', 'c524a285789d961960ffa6dfc51bfe97', 'c524a285789d961960ffa6dfc51bfe97']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

