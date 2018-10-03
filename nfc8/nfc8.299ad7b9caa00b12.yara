
rule nfc8_299ad7b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.299ad7b9caa00b12"
     cluster="nfc8.299ad7b9caa00b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos smforw"
     md5_hashes="['109a7b5d6edbcba518f3e9615ba0f0eacc04bc1c','5f4e6fe4a86b15786d9b28827473ef0d7abd2783','12374500d5af0e7eb5f9801dae17e51463903de5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.299ad7b9caa00b12"

   strings:
      $hex_string = { 7d4ba0ba7f40e723e88b5692948f58503a5d801c862bf31304fdbbc4460597640f257c29aaa9067288ccaff4b8f220a70a6dd1deeed948985e34c83119a8275f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
