
rule n3ed_630618f99ec31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.630618f99ec31932"
     cluster="n3ed.630618f99ec31932"
     cluster_size="179"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox graftor unwanted"
     md5_hashes="['01128fcfab71320341f1f11bcbc0938c','013f413dadbbb8f09c5653973a31ec0f','143cb3da7c5020124f6eb0d61a67b2d9']"

   strings:
      $hex_string = { 04020000696d756c0000000000000000000000000041050700210407002106120000000000840000000000000000000000000000020000000108000070757368 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
