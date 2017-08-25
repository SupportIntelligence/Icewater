import "hash"

rule k3e9_51b93126dda30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93126dda30b32"
     cluster="k3e9.51b93126dda30b32"
     cluster_size="50 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ec31874ffe7f0011efaaa7f9f9570628', 'c0c71af9bf371b8dfdd9a3a614abad9f', 'd27f77e2f7072818b748877b21cbd612']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4864,256) == "a123699e38ecb694dc0255cec9d6cbbb"
}

