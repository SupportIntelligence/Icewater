import "hash"

rule m3e9_1c3a9cc1c8000922
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1c3a9cc1c8000922"
     cluster="m3e9.1c3a9cc1c8000922"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy androm backdoor"
     md5_hashes="['7ef0eb6efda62187499424e7b26452af', 'e648236919e6e642c785902940829e90', '99da9c22ca9f32eb4d001d8a90e458f7']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(20480,1024) == "13d3268c5c0285305299536cda4475aa"
}

