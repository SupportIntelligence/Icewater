import "hash"

rule k3e9_2316f3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2316f3e9c8000b12"
     cluster="k3e9.2316f3e9c8000b12"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy backdoor simbot"
     md5_hashes="['d171e5252b6b709720be1ca1b0c8a5dc', 'bd4f36c0be5e5d90da0c14b141111c15', 'a70c41ebcc73840ba9072ab82a1a3ae3']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

