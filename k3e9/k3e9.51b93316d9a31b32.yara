import "hash"

rule k3e9_51b93316d9a31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93316d9a31b32"
     cluster="k3e9.51b93316d9a31b32"
     cluster_size="65 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a44530fc76c93e30e771845a4cbaf786', 'd995f8bbe40d309fb9f5b4630e301a4c', 'e9eeb3e69ea70ef5a10920cb774a990b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

