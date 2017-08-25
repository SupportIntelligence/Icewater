import "hash"

rule k3e9_51b13336d5a30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13336d5a30b32"
     cluster="k3e9.51b13336d5a30b32"
     cluster_size="53 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bb7ffbc09d37ebf1055720065a5b0520', 'f11baf3e4255e52a2e15ea5450abe2b0', 'a4a0dd80e68f6bd4c1a4145f82d37af5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

