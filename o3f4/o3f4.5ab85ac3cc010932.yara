
rule o3f4_5ab85ac3cc010932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f4.5ab85ac3cc010932"
     cluster="o3f4.5ab85ac3cc010932"
     cluster_size="1719"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="idlekms hacktool tool"
     md5_hashes="['00548027f8b1470175f942c86648c5c0','00873e9e122ff6617e62bfe8ee4d0c2a','02597cc4eecef6bb486c6e74bef6f196']"

   strings:
      $hex_string = { 05e33ed8123905f73e2e1b7902ff3e001499038a31411b5105133fef1049041d3f871259058b0222002100373f521b4100503f581b11018b025e1b69056a3fb6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
