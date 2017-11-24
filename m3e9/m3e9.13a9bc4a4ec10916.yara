
rule m3e9_13a9bc4a4ec10916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13a9bc4a4ec10916"
     cluster="m3e9.13a9bc4a4ec10916"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious unwanted"
     md5_hashes="['027fba051c7268b0dcdf454ba03fbfa2','14c8384dea2776ca403ca1e3338fd943','fa3ea2c693ccfd900c33acdde4e0c14e']"

   strings:
      $hex_string = { 0d8de4833e3416c7b873b92475221e07a70e4abe7ba3ffd1ab477a85d55da92ad95c0312427f88a196009a1893adbfe986c25a1969b41f1c57ee745ffe11232e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
