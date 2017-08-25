import "hash"

rule k3e9_63146da11c8a7b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da11c8a7b16"
     cluster="k3e9.63146da11c8a7b16"
     cluster_size="93 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['cef9158653e24e3b8e8da7b19df2fabd', 'd56cdd56671fb0a23170e1c7c206f8c9', 'a65d14e85e37571f7fb1a17faff69a27']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

