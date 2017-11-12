import "hash"

rule m3e9_09b2cd26d6bb1916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.09b2cd26d6bb1916"
     cluster="m3e9.09b2cd26d6bb1916"
     cluster_size="55 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="gepys lethic shipup"
     md5_hashes="['d483acb12679dff100cacdd3b72d4b0f', '52a5c2d025ba0a25983408973c4c95e3', '7824664e0d4d1b5d6301738e568f30a6']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(22528,1024) == "8e532b6a62eb785016ec08be8cd48c50"
}

