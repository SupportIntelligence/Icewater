import "hash"

rule k3e9_51b133369da31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b133369da31132"
     cluster="k3e9.51b133369da31132"
     cluster_size="174 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d2e990d3c3595ea4c6e6f1a5d252970e', 'bcaa660bd94ce867341dd9b923daf629', '0be1e85327e5842bc359a3b3eab4d096']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,1024) == "5ab8258470efa3d600fcbe17d59a8cd4"
}

