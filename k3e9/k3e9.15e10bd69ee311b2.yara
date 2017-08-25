import "hash"

rule k3e9_15e10bd69ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e10bd69ee311b2"
     cluster="k3e9.15e10bd69ee311b2"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ba682a8b909186051c7a7cf889354bac', 'ba682a8b909186051c7a7cf889354bac', 'd5959c29148af7e52a48d4def56b2a06']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "479d8ddd4ba5d72b0f7fc8167a804cd4"
}

