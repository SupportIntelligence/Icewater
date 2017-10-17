import "hash"

rule m3e7_2b17ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.2b17ea48c0000b12"
     cluster="m3e7.2b17ea48c0000b12"
     cluster_size="43 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="mira ahruw finj"
     md5_hashes="['b0aba090f7eb6b1270d086cc583ea299', '603fd18af2b3250c9a63a04c72f2a01d', 'b3a0d467aa256a0a1ed2b1e924b37bc3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(45246,1028) == "1fbea4ffab64868cf28654cd6a9b6071"
}

