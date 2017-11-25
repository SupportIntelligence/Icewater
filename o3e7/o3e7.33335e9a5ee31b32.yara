
rule o3e7_33335e9a5ee31b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.33335e9a5ee31b32"
     cluster="o3e7.33335e9a5ee31b32"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr malicious dlboost"
     md5_hashes="['0478109934a8abcb79a6ff73c7d68a19','3ee4fa259de20bab1e36c96e4b98cb29','d2332ff93ea421b0915ea6dd112f2139']"

   strings:
      $hex_string = { 004142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
