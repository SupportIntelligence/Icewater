import "hash"

rule k3e9_6b64d34f9b6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f9b6b5912"
     cluster="k3e9.6b64d34f9b6b5912"
     cluster_size="446 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['feed173ece9a4141f48f14bf42cfe7f5', '78865f885bf41d13b8dc90406d77bfd6', '9d47d44f44615d88bc795b32163e0199']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(19648,1036) == "dbc5e24a5c7f08cf7d6715f88a9b1785"
}

