
rule k26bb_293b1c6098d96996
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.293b1c6098d96996"
     cluster="k26bb.293b1c6098d96996"
     cluster_size="86"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore alphaeon malicious"
     md5_hashes="['896370745faf208d88910df3501779f500716be9','43ae86ec97a741e15f554b16f4fd561c398c400f','ed4bfa7ed7849c8d00d610247d34f155b6e9cd73']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.293b1c6098d96996"

   strings:
      $hex_string = { d0c516e093ad4f430044b48f9234fa568a9cd903b1056042d5f7b72164145331fc9f49488d6ba1cae18139ce5f332cf65861d3db98173d6c7f09dee60b3bf8fe }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
