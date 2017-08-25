import "hash"

rule k3e9_6b64d34b0b4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b0b4b4912"
     cluster="k3e9.6b64d34b0b4b4912"
     cluster_size="36 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['0cd31d2d8cceb520114920216c4471f2', 'd0331216858f4a9a9f2368e5f1e156ee', 'aead290825e424e323a6dbd0b8882227']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8192,256) == "b36bd97e697e1a8c585291e6cbcffcf4"
}

