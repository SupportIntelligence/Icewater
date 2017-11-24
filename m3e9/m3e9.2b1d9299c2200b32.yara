
rule m3e9_2b1d9299c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2b1d9299c2200b32"
     cluster="m3e9.2b1d9299c2200b32"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['01389e98ec5a0aec9f15eed6231021df','14e1f3c93b725d058ca18cbdbae13b33','f1d4351028babc6c4fd432e2795e1696']"

   strings:
      $hex_string = { 6d76eada8bdba8dda995ec5602cfa2b52a27314937c65ef4c520edbc0bf8d64826c1e72384093f9e834623036578b14c3b7733a1689cb2543aca5106533652b9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
