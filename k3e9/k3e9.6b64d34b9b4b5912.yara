import "hash"

rule k3e9_6b64d34b9b4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b9b4b5912"
     cluster="k3e9.6b64d34b9b4b5912"
     cluster_size="920 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['ae6251655817e5d84bf20c8a175dd954', 'a77d9aaa9d0b9f5eb70319c4995b0cfb', '0cc7e99c7b2e0cc6aedb783da74b73b8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6180,1036) == "2b4289c8af774f0b1076619ad1925bff"
}

