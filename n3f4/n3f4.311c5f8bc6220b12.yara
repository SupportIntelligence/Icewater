import "hash"

rule n3f4_311c5f8bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.311c5f8bc6220b12"
     cluster="n3f4.311c5f8bc6220b12"
     cluster_size="22383 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy injector jorik"
     md5_hashes="['07b6a79b4c5872f72c75c2d2a8ef745d', '0221c36f7a1dabaf0b2b6f4e92a27068', '03f0a09c57cb68bd613c4c76e6e75335']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(2048,1024) == "92a4a1fd8305cb2a5d8e4ec7b738f7b1"
}

