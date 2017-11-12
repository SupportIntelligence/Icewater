import "hash"

rule k3e9_3a66218782220120
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3a66218782220120"
     cluster="k3e9.3a66218782220120"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['02eb406394eb96b1857677fc43f40f3c', 'ce3c21cafad05e94f15af455ce4abac0', '02eb406394eb96b1857677fc43f40f3c']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(14336,1024) == "06205301e9512d0624cf178a60d915b7"
}

