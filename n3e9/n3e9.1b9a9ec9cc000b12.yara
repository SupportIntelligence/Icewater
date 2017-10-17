import "hash"

rule n3e9_1b9a9ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b9a9ec9cc000b12"
     cluster="n3e9.1b9a9ec9cc000b12"
     cluster_size="2093 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="domaiq bundler tugspay"
     md5_hashes="['11befa9a327c9c03f5da11e76c126484', '1d11983f96379494c12001c6ac194462', '026cb71d3f73ddb4415452ec56935ed4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(226711,1025) == "914854affdd06982808c5690ea32a0af"
}

