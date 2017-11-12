import "hash"

rule k3ec_379a5ef8ce850b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.379a5ef8ce850b32"
     cluster="k3ec.379a5ef8ce850b32"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine heuristic"
     md5_hashes="['f0f06dd85562f256ab934655e8b0efcc', '8fb11139bf0e5429d9c0f961a14fde1b', 'f0f06dd85562f256ab934655e8b0efcc']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(35328,1536) == "999736f3764b622e493be268181ce18c"
}

