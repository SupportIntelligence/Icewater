
rule n3f7_0b9b1ce1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.0b9b1ce1c2000b12"
     cluster="n3f7.0b9b1ce1c2000b12"
     cluster_size="49"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack clicker clickjack"
     md5_hashes="['02a3137b559d7cfbb00c86f55faa2843','043aeca3a22380f0ec34e7b9365e91e7','44401fa138f8f559a689a894c35a505f']"

   strings:
      $hex_string = { 2f253235285b302d39612d66412d465d7b327d292f672c222524312229292c633d746869732e482c6e756c6c213d632626612e7075736828223a222c53747269 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
