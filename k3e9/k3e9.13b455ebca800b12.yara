import "hash"

rule k3e9_13b455ebca800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13b455ebca800b12"
     cluster="k3e9.13b455ebca800b12"
     cluster_size="1966 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="generickd upatre zbot"
     md5_hashes="['24ccdf10b6c54b63ee02b1770c4dcd46', '8abd19c72bf734ffec9b61e2c6422850', '8abd19c72bf734ffec9b61e2c6422850']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1024) == "e817887e94cc763cce2d3cc989d25b5e"
}

