import "hash"

rule m3eb_5990acc99e230b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3eb.5990acc99e230b32"
     cluster="m3eb.5990acc99e230b32"
     cluster_size="254 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="runbooster giggwl hochx"
     md5_hashes="['d52261f5bc593426e2b975b82a3a7ad1', 'fbacf726f5c46853e2373678a96697e1', 'a9393dcc8c49f5f39b6365149a16d7bd']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(26624,1024) == "5defa325df3dc2d672a942cd4b2cefe4"
}

