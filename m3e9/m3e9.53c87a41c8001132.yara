import "hash"

rule m3e9_53c87a41c8001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.53c87a41c8001132"
     cluster="m3e9.53c87a41c8001132"
     cluster_size="167 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre ipatre kryptik"
     md5_hashes="['b747f6d0b8733ef1acf9d945913d99d3', 'c77952836cdca82147e7f5efd0c4dbed', 'b335412f4a6c5095aba1dce5cd2c669d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(17648,1039) == "7e636bf06777b74fe58b5ffc559ab6b8"
}

