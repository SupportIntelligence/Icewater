import "hash"

rule k403_139614f9c9000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k403.139614f9c9000b16"
     cluster="k403.139614f9c9000b16"
     cluster_size="2806 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="hackkms risktool riskware"
     md5_hashes="['11cc321bd9dc9a6026f08c696590ca99', '1095f4240c2dd4d51d93bf1f96d3e5c5', '0dc93573a8406d9dcd596457022dc1c9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24576,256) == "bd628c11c1c19c9e0dca9d6fa37ff9f5"
}

