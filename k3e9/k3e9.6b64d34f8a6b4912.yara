import "hash"

rule k3e9_6b64d34f8a6b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f8a6b4912"
     cluster="k3e9.6b64d34f8a6b4912"
     cluster_size="55 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['cb5e915bdd0e519eec9411d063621d23', 'c11d1ce5f6ca936c98d083345db29fa8', '0fdee2d39222fbbe3cc642ca3311b074']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(14468,1036) == "3fc9b6513c182f90d41c33f933010485"
}

