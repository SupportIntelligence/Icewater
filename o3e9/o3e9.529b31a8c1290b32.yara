import "hash"

rule o3e9_529b31a8c1290b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.529b31a8c1290b32"
     cluster="o3e9.529b31a8c1290b32"
     cluster_size="66 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy linkury bdff"
     md5_hashes="['f9ceb543adadeb5dd801954f01eab0b5', '7bac07529ff07de2da104cee58596c65', 'd0f344992b6781562bead7ca4a4b04be']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(853504,1024) == "645760a3cb41ab07706594b9cc4adc00"
}

