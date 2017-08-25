import "hash"

rule k3e9_51b1332655a31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b1332655a31b32"
     cluster="k3e9.51b1332655a31b32"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b4b806d4689a5202c882c6e8b672658b', 'd411af1cf5dc61b392d6b181faf24aa6', 'c0f2858bbd216cd7cd801d9410e02743']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12544,256) == "0d3081d09f971c3c9d786caf79ac8fb7"
}

