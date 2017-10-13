import "hash"

rule m3e9_6918d18b96427b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6918d18b96427b32"
     cluster="m3e9.6918d18b96427b32"
     cluster_size="65 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="vbkrypt symmi vbcrypt"
     md5_hashes="['a04ce26743d25f0e3bc981d17945d9b7', 'd3c61df5c20e72c6664c174d3ce75721', 'ac94446aa79fe2f9db36bf54ac5a1ef6']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(30720,1024) == "e31ffb95dbbc4d11a42ea0823f11c556"
}

