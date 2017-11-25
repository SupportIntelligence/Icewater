
rule m3f7_51999099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.51999099c2200b12"
     cluster="m3f7.51999099c2200b12"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0bdd5ca9f00a504c1d423ba9ba7ff918','101b47dc3dedabc6696e397b6dec99e0','ea7860420ed4c4abc106f8e2e186d604']"

   strings:
      $hex_string = { 6369616c466f6c646572283229202620225c2220262044726f7046696c654e616d650d0a49662046534f2e46696c654578697374732844726f7050617468293d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
