import "hash"

rule k3e9_6b64d36f986b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36f986b5912"
     cluster="k3e9.6b64d36f986b5912"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['43cba051ab9f2cda6186f9f589d6655e', '9ad02c12c03fdca4cbfdf38346843ca3', 'b7c275c818eaefd653e9f9251f32e9d4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1792,256) == "e968e938e7851d6777e2e0a561e83aca"
}

