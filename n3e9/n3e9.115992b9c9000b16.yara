import "hash"

rule n3e9_115992b9c9000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.115992b9c9000b16"
     cluster="n3e9.115992b9c9000b16"
     cluster_size="60 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['cd76ba006511cfb05c6362324eb8f5d7', 'a5bdf1e619fca392d17a05ef51e160f4', 'bf8bfcae9f906ac5ddb00b8e070be93c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(195584,1152) == "a65d524274c61b52c50b4f8a9faef5d7"
}

