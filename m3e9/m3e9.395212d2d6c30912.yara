
rule m3e9_395212d2d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.395212d2d6c30912"
     cluster="m3e9.395212d2d6c30912"
     cluster_size="25"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['02a95751e1f119718388c233583fc408','0bfdd0c09232757ba98a6975bd7a34af','a0b91b6d36b950d275263b5c88ce68ba']"

   strings:
      $hex_string = { a5c8857be7b803ea7d101b0d715231a35d554cac07d8462cefbc06bb04fc8ade2ad2d73ed149b735ed901c10f3e56ba069486de69cb41930bab609aeb1a43a7c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
