import "hash"

rule n3e9_1b257ec148000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b257ec148000912"
     cluster="n3e9.1b257ec148000912"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="pykspa vilsel chydo"
     md5_hashes="['6691f3155eaad22c13cb8821ef88c0b4', 'd1ce5faac6970110ad508119f8a8d514', '6691f3155eaad22c13cb8821ef88c0b4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(22528,1024) == "7447e0459ef17a0f37e395a0e796e723"
}

