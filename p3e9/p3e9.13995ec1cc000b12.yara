import "hash"

rule p3e9_13995ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.13995ec1cc000b12"
     cluster="p3e9.13995ec1cc000b12"
     cluster_size="1409 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ircbot backdoor dorv"
     md5_hashes="['a9b03b5ac663b29c13b0f22e9f2252fe', 'a88204b09cd5ef2f59ff01eae61a891d', 'ae5f2613f05da5ac17da4d35509145a0']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(79788,1030) == "d3e5be795e3c1744053621665c7c209d"
}

