import "hash"

rule p3e9_11995ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.11995ec1cc000b12"
     cluster="p3e9.11995ec1cc000b12"
     cluster_size="8071 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="ircbot backdoor dorv"
     md5_hashes="['06c48117efe244bd32323c08f5cf8bd7', '0f29bf6acac11ea08a1821149205ec73', '07f5c7a3bb98018a659d6ce9ae04c085']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(79788,1030) == "d3e5be795e3c1744053621665c7c209d"
}

