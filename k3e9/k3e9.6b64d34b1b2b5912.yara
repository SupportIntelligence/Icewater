import "hash"

rule k3e9_6b64d34b1b2b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b1b2b5912"
     cluster="k3e9.6b64d34b1b2b5912"
     cluster_size="24 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['a68e6ea3c86b860401dcad99b0ea6b51', 'a6ce57a4b59cd0aaaae45e0cfaee4f9c', 'bc67a73f7bcbf3f28feadc9cf739c6a3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,256) == "b99b5cf10e3c3d9af872a74a92ecec2b"
}

