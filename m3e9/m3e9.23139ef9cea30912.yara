import "hash"

rule m3e9_23139ef9cea30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.23139ef9cea30912"
     cluster="m3e9.23139ef9cea30912"
     cluster_size="1196 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine high"
     md5_hashes="['284f6b437eed3e202a33315d15c3a86c', '31dab8847e405d0b6455b6bd7764975f', '2969f6cd7958cfa0e78066695093e7c2']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(135680,1110) == "5381992b584f01bcfd8d0323d63b44e8"
}

