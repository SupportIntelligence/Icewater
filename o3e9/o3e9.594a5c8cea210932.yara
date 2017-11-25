
rule o3e9_594a5c8cea210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594a5c8cea210932"
     cluster="o3e9.594a5c8cea210932"
     cluster_size="190"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="strictor riskware dealply"
     md5_hashes="['01653a36c07a284689feaedd8636a14d','029fa7b2c0bc431371c3996c23117c7d','0f4e4fdec5fea0212191b69c0719a226']"

   strings:
      $hex_string = { 0072002000270025007300270020006e006f007400200066006f0075006e006400050041007000720069006c0003004d006100790004004a0075006e00650004 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
