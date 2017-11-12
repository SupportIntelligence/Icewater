import "hash"

rule m3e7_2b1341b29cabdb12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.2b1341b29cabdb12"
     cluster="m3e7.2b1341b29cabdb12"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ccpk mira icgh"
     md5_hashes="['3037f6950e734fe28402735b656ec654', '96fb4ad460888e46c86139095646c0fe', '3037f6950e734fe28402735b656ec654']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(109674,1025) == "60e7d7d4deb67dfe1d2c3ae6953f36e3"
}

