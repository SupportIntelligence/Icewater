import "hash"

rule k3e9_6b64d34b1a6b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b1a6b4912"
     cluster="k3e9.6b64d34b1a6b4912"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['ae76df31b9ffcd713f1b4daf9dc81689', 'bc0c1e00ae3e5242fbf6e300caa5b40b', 'c7e1bd392da068d7719c486c0d97dccf']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(21504,1024) == "fed41aa492b575fa0024f13ad4c5fd5e"
}

