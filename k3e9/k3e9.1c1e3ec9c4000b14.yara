import "hash"

rule k3e9_1c1e3ec9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1c1e3ec9c4000b14"
     cluster="k3e9.1c1e3ec9c4000b14"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="simbot backdoor razy"
     md5_hashes="['d3ad9aed4685cd340ebd545cf2f73c53', 'a33ff6530ce057e699549ac0edde95d7', 'ca12a763fbb06867e018cb293c63a193']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

