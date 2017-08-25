import "hash"

rule k3e9_6b64d36b9b4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b9b4b5912"
     cluster="k3e9.6b64d36b9b4b5912"
     cluster_size="85 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['a862f73db693a100b5f03454139ccb74', 'bc8befdf8271272581cbedaa7e88bda2', 'b3819830006c17cd5519543e6beabafd']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6180,1036) == "2b4289c8af774f0b1076619ad1925bff"
}

