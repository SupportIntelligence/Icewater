import "hash"

rule m3e9_61183ac1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61183ac1cc000b32"
     cluster="m3e9.61183ac1cc000b32"
     cluster_size="521 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171018"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['7e4164204683579654b0791fcad2b6d2', '60352f858e56464dbc5dcd0232eb06cd', '60352f858e56464dbc5dcd0232eb06cd']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(61952,1024) == "6a039dc6f36c112b920bef9b8a73cb0e"
}

