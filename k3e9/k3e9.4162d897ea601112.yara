import "hash"

rule k3e9_4162d897ea601112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4162d897ea601112"
     cluster="k3e9.4162d897ea601112"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['59dc1ef39b7230bb918ced40742cf7bc', 'b3357da7bcfe73d48d38249d7e0d0cd6', '43bdf585f49b06f5a4521eee5cdc18d4']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(1024,1024) == "c6e0a64fce02608f75de0e6323f758c0"
}

