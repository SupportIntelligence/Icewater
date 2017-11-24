
rule k3e9_42963841c8001112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.42963841c8001112"
     cluster="k3e9.42963841c8001112"
     cluster_size="1167"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zbot generickd trojandownloader"
     md5_hashes="['007be44c602760da02d296048fab242d','00f3c72e0a03cbdf392a5cb8c45afc13','07a734d0826719ee7d7fcb75eda60076']"

   strings:
      $hex_string = { 74496e666f3e0d0a3c2f617373656d626c793e009a0680014dec5b7e068001956b77560880010de6a7cd0b800139faca6d0680018999d5670c8001c8c5bea605 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
