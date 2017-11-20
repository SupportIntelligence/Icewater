
rule m3e9_3a58b31bc2220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a58b31bc2220b14"
     cluster="m3e9.3a58b31bc2220b14"
     cluster_size="26"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['271458fa39e3bc349354a0b95db21a3d','277e69b21816a7a94bf454c48b016347','c9a32fff741999fa8b8e5643740d2bba']"

   strings:
      $hex_string = { 626a601b11bb503ce2ec539e6e07ab7066c027721f56bc0ea9be6534b24e7fb722ee080d03918e4700856d0c97052375a8c986052530ce96f27b242163871851 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
