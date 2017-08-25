import "hash"

rule k3e9_6b64d34b0a4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b0a4b5912"
     cluster="k3e9.6b64d34b0a4b5912"
     cluster_size="86 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['ac68853e1087b62f29948286f01f5347', 'c779c1238eea95a3d0d11051416cab08', 'ab4f8e6f83a02901075bb231f10f8630']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1792,256) == "e968e938e7851d6777e2e0a561e83aca"
}

