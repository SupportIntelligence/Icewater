import "hash"

rule p3e9_11991ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.11991ec1cc000b12"
     cluster="p3e9.11991ec1cc000b12"
     cluster_size="4925 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="ircbot backdoor dorv"
     md5_hashes="['08131c15abd7ca5e5781bcf0e62d84d2', '1b84818addcc1457def142c0116f9a6a', '193f3e3ff91df3d37763a3fdc5d891db']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(79788,1030) == "d3e5be795e3c1744053621665c7c209d"
}

