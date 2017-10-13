import "hash"

rule p3e9_13995ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.13995ec1cc000b12"
     cluster="p3e9.13995ec1cc000b12"
     cluster_size="1303 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ircbot backdoor dorv"
     md5_hashes="['7a373fef6a6f0b6fe148b9f6c725ac99', '1d7d1f5070bc59b336c0f22324c68655', '849edecc637d2dfb14226a6a344403c6']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(79788,1030) == "d3e5be795e3c1744053621665c7c209d"
}

