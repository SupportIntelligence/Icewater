import "hash"

rule k3e9_391491e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391491e9c8800b32"
     cluster="k3e9.391491e9c8800b32"
     cluster_size="55 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['cedbd9a762218565f06b9422430e7c76', 'ada6d343484c9e705ba8a9bbfdbadf8f', 'a173ba3ba4672c99733299c1305e293e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1195) == "482beaebbdc1ed3d7533b440ec3ba87c"
}

