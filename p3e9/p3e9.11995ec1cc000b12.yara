import "hash"

rule p3e9_11995ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.11995ec1cc000b12"
     cluster="p3e9.11995ec1cc000b12"
     cluster_size="8523 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ircbot backdoor dorv"
     md5_hashes="['0e997e811fda6e4ab1a4aa2af4fecedc', '0068968451ecbbbf7b8d12fe3fff700f', '0dffe535f66f974857b1faa1745b1b4f']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(79788,1030) == "d3e5be795e3c1744053621665c7c209d"
}

