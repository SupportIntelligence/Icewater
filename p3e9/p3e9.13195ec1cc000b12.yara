import "hash"

rule p3e9_13195ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.13195ec1cc000b12"
     cluster="p3e9.13195ec1cc000b12"
     cluster_size="721 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ircbot backdoor dorv"
     md5_hashes="['b084b2387fbc99fa64d42ebe6d63c17d', 'bdc3cc08ac69b86dc4f3ef600d46e6c5', 'c93d969f011b7b2efce21682d1cb0a47']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(79788,1030) == "d3e5be795e3c1744053621665c7c209d"
}

