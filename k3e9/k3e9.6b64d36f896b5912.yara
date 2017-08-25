import "hash"

rule k3e9_6b64d36f896b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36f896b5912"
     cluster="k3e9.6b64d36f896b5912"
     cluster_size="95 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['c520ba2f8d51b4f08912ac2ea2bce669', 'b77201dc5fbfc3d158ee196ac22542ed', 'aa7693d43024e42677a6ea7ce3e230ba']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1792,256) == "e968e938e7851d6777e2e0a561e83aca"
}

