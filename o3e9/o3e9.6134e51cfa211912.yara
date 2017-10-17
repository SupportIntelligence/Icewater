import "hash"

rule o3e9_6134e51cfa211912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6134e51cfa211912"
     cluster="o3e9.6134e51cfa211912"
     cluster_size="81 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ardamax fakealert keylogger"
     md5_hashes="['00e6da351d4557357f30f10c193bf8c7', '6464c1e04b1bfa8c9b6e68199f542fbf', 'ab0ce8f7aed2bebe48ec34c96ecc701f']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(49152,1024) == "13a6aef89f39f5136c40aea6bb97f36a"
}

