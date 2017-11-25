
rule m3f7_199c6a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.199c6a48c0000932"
     cluster="m3f7.199c6a48c0000932"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['1c3d678d9f6b058d3352d6219abd0c33','862ab6b09dea6f04855fa0062d7d6515','fe204e28daf530bb7ef0ba246cd45f10']"

   strings:
      $hex_string = { 414143592f467551532d643768784d512f533232302d7338302f6469615f6d69727a615f6c617267652e6a7067272077696474683d273731272f3e0a3c2f613e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
