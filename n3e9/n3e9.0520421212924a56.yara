
rule n3e9_0520421212924a56
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0520421212924a56"
     cluster="n3e9.0520421212924a56"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy delf asacky"
     md5_hashes="['2b74575dd9a9a6e3d667514a1205c10a','39bb81305f9a15aef9aa2986a7c6dbd3','912d65e406f302d8505a911cea9362a7']"

   strings:
      $hex_string = { 7a5699f8eeeb86d1829d7984766ab4555ae3a1a25d316c41548339fe6653cba922ada6358bdefdb1bfc764faba85e0b6870ee907f211e28a0bab6973f5aaec8f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
