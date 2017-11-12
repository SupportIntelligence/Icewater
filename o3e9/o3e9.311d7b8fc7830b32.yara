import "hash"

rule o3e9_311d7b8fc7830b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.311d7b8fc7830b32"
     cluster="o3e9.311d7b8fc7830b32"
     cluster_size="3168 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor genome hupigon"
     md5_hashes="['0e7de05a85b92aa0fd56bba1539e9f49', '26afe14179f220edadd36da57fe11ae7', '189b8385c15da1000b96d6aa0262fd01']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(188416,1024) == "a848a2906093ba9ffa0c6edc2efb74e5"
}

