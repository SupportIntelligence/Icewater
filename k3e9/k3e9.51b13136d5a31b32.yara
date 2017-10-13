import "hash"

rule k3e9_51b13136d5a31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13136d5a31b32"
     cluster="k3e9.51b13136d5a31b32"
     cluster_size="139 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ac2e8f99801b2598cff427cf9476e4c6', 'f10fe8e4dccabd9344d74f77e873ccf9', 'a0e0b88645dbe1d00db22c6521cb9f60']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

