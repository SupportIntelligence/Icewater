import "hash"

rule k3e9_6b64d34b896b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b896b4912"
     cluster="k3e9.6b64d34b896b4912"
     cluster_size="19 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['9194b99fb3c9d7a084e875be5027c7aa', 'dc2c100e04e466f640b1105ecb5a01ce', 'd4c74c2753ee50666de34ea4ff9c68a8']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(19648,1036) == "dbc5e24a5c7f08cf7d6715f88a9b1785"
}

