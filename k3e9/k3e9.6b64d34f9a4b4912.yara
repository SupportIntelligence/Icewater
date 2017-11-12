import "hash"

rule k3e9_6b64d34f9a4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f9a4b4912"
     cluster="k3e9.6b64d34f9a4b4912"
     cluster_size="92 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['ca3bae9fcb7869a6ed67b41804089265', 'b4631832fbe1e8e4d8b9836747410654', '35adc95a088a83cd3e639006282bf06e']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(12396,1036) == "647cd7f4094d87659d4644490060e83e"
}

