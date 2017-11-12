import "hash"

rule m3e9_29567ae9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29567ae9c8800b32"
     cluster="m3e9.29567ae9c8800b32"
     cluster_size="209 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="madangel small madang"
     md5_hashes="['b446fe65c8e9a672b54d88646de79ccb', '4ef7687eb8c07a607ca0120df5ea2865', 'f9fb6a4eb9dfcfaeb2ef0f0dd8a374c0']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(21720,1042) == "53d6812870249449e4886988f42d0516"
}

