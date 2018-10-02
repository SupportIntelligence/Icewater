
rule k26bb_293b18609cd96996
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.293b18609cd96996"
     cluster="k26bb.293b18609cd96996"
     cluster_size="213"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious unwanted"
     md5_hashes="['5fdb53004f209d8bb2feb5da0c5ee904c5615e50','0060e933fc078dda3014c53ca1b91f3ca422fe5f','342d82d148cc02035005f30f3c903f4e80e4b719']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.293b18609cd96996"

   strings:
      $hex_string = { d0c516e093ad4f430044b48f9234fa568a9cd903b1056042d5f7b72164145331fc9f49488d6ba1cae18139ce5f332cf65861d3db98173d6c7f09dee60b3bf8fe }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
