
rule o3e9_594a5c9cea200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594a5c9cea200932"
     cluster="o3e9.594a5c9cea200932"
     cluster_size="177"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['00370de113077d8020c75d0c658b5fe3','00c5849b6a47ad32fa7bcde31cd01dc5','0ea793e4a448c6a45fbca38f5156c578']"

   strings:
      $hex_string = { 72002000270025007300270020006e006f007400200066006f0075006e006400050041007000720069006c0003004d006100790004004a0075006e0065000400 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
