import "hash"

rule k3e9_3c18bac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c18bac9c4000b14"
     cluster="k3e9.3c18bac9c4000b14"
     cluster_size="103 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy simbot backdoor"
     md5_hashes="['bb138bfb8b1984ac620af624b6a3b9a3', 'acd55f214494f8ae004649836eab28ce', '5f0e0e86f3ecb344888846714f3372e8']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

