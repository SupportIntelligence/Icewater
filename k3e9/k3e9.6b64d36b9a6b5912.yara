import "hash"

rule k3e9_6b64d36b9a6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b9a6b5912"
     cluster="k3e9.6b64d36b9a6b5912"
     cluster_size="91 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['aa44f4916539946680957b921c72c135', 'c50be94714a9d4e727b1e1ce7c4fc2b5', 'a9f2c2aaf1b6071288bd877a7611ef87']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4108,1036) == "3ff2cd201667fa9cb045d19e7527baca"
}

