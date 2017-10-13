import "hash"

rule n3f4_311c5f8bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.311c5f8bc6220b12"
     cluster="n3f4.311c5f8bc6220b12"
     cluster_size="8908 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zusy injector jorik"
     md5_hashes="['02a5274919fc060360ddc1ae8008773f', '088af19e4eef25f7db737aa451ee9fc9', '060f731020a55b0c2996be02fd85ee2f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(2048,1024) == "92a4a1fd8305cb2a5d8e4ec7b738f7b1"
}

