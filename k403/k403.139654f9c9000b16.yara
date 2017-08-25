import "hash"

rule k403_139654f9c9000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k403.139654f9c9000b16"
     cluster="k403.139654f9c9000b16"
     cluster_size="428 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="hackkms risktool riskware"
     md5_hashes="['0824fc1c17ddf4fcbfc3e513da8e0fd0', '572f9984e0864877b8a480b31e5180f5', '4ae86ec789c4ebec73c6f219e543024c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24576,256) == "bd628c11c1c19c9e0dca9d6fa37ff9f5"
}

