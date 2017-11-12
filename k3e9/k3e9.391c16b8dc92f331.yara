import "hash"

rule k3e9_391c16b8dc92f331
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c16b8dc92f331"
     cluster="k3e9.391c16b8dc92f331"
     cluster_size="50 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['c48f6f8abc4254a66862b87668134882', 'd283633b9d40571a7f0a1ce53d88fbdf', 'e669c879938adb42f346bb6acd3b5143']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(18944,1024) == "5af8e6673660355cdb3cd3e418c60627"
}

