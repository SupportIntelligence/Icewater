import "hash"

rule k3e9_6b64d36f9d6b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36f9d6b4912"
     cluster="k3e9.6b64d36f9d6b4912"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['e8ca33a37418de8b61b3c697c014783e', 'e8ca33a37418de8b61b3c697c014783e', 'e69577ff9ad5f433555a7bcdb1c88286']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1280,256) == "8e02667518727a374c2e7f899e82f609"
}

