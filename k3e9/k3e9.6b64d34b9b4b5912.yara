import "hash"

rule k3e9_6b64d34b9b4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b9b4b5912"
     cluster="k3e9.6b64d34b9b4b5912"
     cluster_size="672 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['3ad13bf2a6f5fea4d2e1e76834e53412', '4568970a11887dd3b4b0e8a828f1e270', '2669b31b7fbc5367cab63b386495c7a9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9288,1036) == "2a5ed0a6e568c6168dc9cdc440a1598c"
}

