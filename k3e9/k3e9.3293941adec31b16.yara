import "hash"

rule k3e9_3293941adec31b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3293941adec31b16"
     cluster="k3e9.3293941adec31b16"
     cluster_size="136 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bb4a1ad3ac83ba3d953d069ebf821b76', 'e995b93ef67eadff11285a4f969cbf04', 'c3b6acdc2e29d6e5cee47c188abda4da']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15360,256) == "cc66ac3c5629854ed877c268c081b668"
}

