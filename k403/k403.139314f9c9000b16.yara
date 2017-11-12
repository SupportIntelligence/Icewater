import "hash"

rule k403_139314f9c9000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k403.139314f9c9000b16"
     cluster="k403.139314f9c9000b16"
     cluster_size="1537 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="hackkms risktool riskware"
     md5_hashes="['4d2ed5d1fee6460bc8aed99fc8ffec5c', '14b272aaa88696c051bc1089e1717182', '2babbb3e4a3360a4027b10bafb29de04']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "279ce4b1ac1ed45a1248ecc22de3d771"
}

