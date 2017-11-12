import "hash"

rule m3e9_16d1bb914a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d1bb914a9664f2"
     cluster="m3e9.16d1bb914a9664f2"
     cluster_size="312 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shipup razy zbot"
     md5_hashes="['43dfc9506695b6a27e7af320e6715a7f', 'a55f8d2bcfd90a4125c9b077238b1aac', 'f06315d7e09e3c339a689a3e9c34c890']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(2048,1024) == "9967db6677f0ed6b8e78591467bc9e49"
}

