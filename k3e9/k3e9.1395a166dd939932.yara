import "hash"

rule k3e9_1395a166dd939932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395a166dd939932"
     cluster="k3e9.1395a166dd939932"
     cluster_size="176 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['5a893a1155425728d967de5fc735ff40', 'ce876a04c0a97e00752c69808001b012', '277e0fad228b24f3c36c63d1ba9edc56']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

