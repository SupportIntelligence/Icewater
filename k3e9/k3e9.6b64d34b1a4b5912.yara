import "hash"

rule k3e9_6b64d34b1a4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b1a4b5912"
     cluster="k3e9.6b64d34b1a4b5912"
     cluster_size="235 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['a2ceaf46b8a3e74bc37ce5fb949e0221', 'b017427b554abf44c760299bffc0c662', '97f96491f7fff8998ad049162b1a7f1f']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(14468,1036) == "3fc9b6513c182f90d41c33f933010485"
}

