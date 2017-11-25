
rule m3f7_2b195ec1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2b195ec1c4000912"
     cluster="m3f7.2b195ec1c4000912"
     cluster_size="9"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script iscp"
     md5_hashes="['1ae07a9ad441bf06c274f67169462472','2d2360989f2632a72d9b0d2c0f898311','fdcb2055f290b197d95f6366e3bf4e17']"

   strings:
      $hex_string = { 343832353739343333353032223e0d0a09093c696d67207372633d222f696d616765732f66616365626f6f6b5f736d2e706e672220616c743d22596f75547562 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
