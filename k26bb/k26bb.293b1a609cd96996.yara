
rule k26bb_293b1a609cd96996
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.293b1a609cd96996"
     cluster="k26bb.293b1a609cd96996"
     cluster_size="237"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore alphaeon malicious"
     md5_hashes="['7c0a80e52f8852a92ec53d78c957938ff9960f0c','20fad14743b35de1307d6f84caa76611f2fdfce8','463eb9d4f4a46bbe7e1babd4154b6c442c01bae7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.293b1a609cd96996"

   strings:
      $hex_string = { d0c516e093ad4f430044b48f9234fa568a9cd903b1056042d5f7b72164145331fc9f49488d6ba1cae18139ce5f332cf65861d3db98173d6c7f09dee60b3bf8fe }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
