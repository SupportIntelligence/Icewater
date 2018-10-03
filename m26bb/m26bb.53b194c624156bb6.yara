
rule m26bb_53b194c624156bb6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.53b194c624156bb6"
     cluster="m26bb.53b194c624156bb6"
     cluster_size="110"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="loki ransom gandcrypt"
     md5_hashes="['54cf16697a04a75302d97cb78d48ae3160cc132c','141739bcf18cae0254ccb01cd9b7488491ed38d6','f9e6864c6f2568d0a7f75845b4545614f541bb4a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.53b194c624156bb6"

   strings:
      $hex_string = { 18cd8cd01d963c3f19f29980931f1012b6a48d6a8ec531068fa38af078fe167ce7e985bfb4a9d729f695432f9c9f3759dfc61749e814054d04c32b0aab8b7158 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
