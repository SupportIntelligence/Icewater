import "hash"

rule m3e9_4b94db68da9ea936
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4b94db68da9ea936"
     cluster="m3e9.4b94db68da9ea936"
     cluster_size="4309 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="wecod symmi urelas"
     md5_hashes="['069acaf773054480afecf5ffc3d23cc1', '244082d0a83a7e7bf0dbb0eebe8c7430', '28c730f58fc928ce261a4eee1cf3faa3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(81920,1024) == "ac1e637480cfb79d008337c529c4687d"
}

