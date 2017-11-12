import "hash"

rule k3e9_2f94e438c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2f94e438c0000b32"
     cluster="k3e9.2f94e438c0000b32"
     cluster_size="491 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bxvp small trojanclicker"
     md5_hashes="['076f258a134d5a1c12a8064248efd64a', 'a398dbc51cc97f365ea41d87ad31e51e', '460a5ddb08a79ea315222c359e95fc31']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(17408,1024) == "a745d823052c2c66c10967651d915e35"
}

