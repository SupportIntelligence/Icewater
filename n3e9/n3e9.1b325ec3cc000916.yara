
rule n3e9_1b325ec3cc000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b325ec3cc000916"
     cluster="n3e9.1b325ec3cc000916"
     cluster_size="24"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa autorun blocker"
     md5_hashes="['216d0cb57c1580ae7c7e0153383643ae','3e144a6eabc9ed44f78c1a250679f16c','c1b14589670bd31ddf181b75e7c5d9f6']"

   strings:
      $hex_string = { 990a347977a8bfc63190063af24f6aaedeaf861ad0d18dd4e0000425dcf7627164c8cf44f1d8265dee18157827f81b95367c12fa2f2ec151e9f43a40b9c25c0e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
