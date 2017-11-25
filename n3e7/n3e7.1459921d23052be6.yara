
rule n3e7_1459921d23052be6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.1459921d23052be6"
     cluster="n3e7.1459921d23052be6"
     cluster_size="45"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler riskware"
     md5_hashes="['043d4a9ccf0b4c4b9e5143d6c30e8c23','086cca949a7a06296b0d62d69e042bcc','69ea02bad2f39d0882bc4ba6477b7cc6']"

   strings:
      $hex_string = { 0072002000270025007300270020006e006f007400200066006f0075006e006400050041007000720069006c0003004d006100790004004a0075006e00650004 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
