import "hash"

rule m3e9_16cb178233d46f96
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16cb178233d46f96"
     cluster="m3e9.16cb178233d46f96"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shipup lethic zbot"
     md5_hashes="['a3ff00e0395950988fc2d11c0c21fa44', 'd6c98c986fe3fbe1bba241959670584a', 'c658d7e91e1bae510050f266fc53b9ef']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(195584,1024) == "02adf856799bf62871c2a5782e74816b"
}

