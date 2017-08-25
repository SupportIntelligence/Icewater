import "hash"

rule k3e9_63146ff11d826b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ff11d826b16"
     cluster="k3e9.63146ff11d826b16"
     cluster_size="255 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['df03fe0ffec6b87c0e1bfdbb03c9afe0', 'ddc451e8aa581c2b0d0beefc144ec9bd', 'c29f999a19594af9eab07a175da0fe72']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

