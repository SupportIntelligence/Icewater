
rule o3e9_5eda3ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.5eda3ec9c4000b12"
     cluster="o3e9.5eda3ec9c4000b12"
     cluster_size="396"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock symmi nabucur"
     md5_hashes="['016c58618cb72d4cdb7ee051b47b0aec','03f4a1090a01612a7dce13ab46d23d84','1929d660c5b98aff08241b78663dff07']"

   strings:
      $hex_string = { 010001002020000002002000a8100000010050414444494e47585850414444494e4750414444494e47585850414444494e4750414444494e4758585041444449 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
