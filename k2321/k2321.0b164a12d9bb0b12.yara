
rule k2321_0b164a12d9bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0b164a12d9bb0b12"
     cluster="k2321.0b164a12d9bb0b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ganelp autorun emailworm"
     md5_hashes="['57cfd9a21609d29beb16a9521c749aa4','61d2ee910f51f79d25041e6cac07c488','fd7f341752206f71cdd2043e771c3848']"

   strings:
      $hex_string = { 45d001265afa058a40d5da753113f110596fea638fe83f4d532a47b57a711a66835de3b6e09722302bcbaf4e17d99ca76c28644b66121f907404df779dcdc488 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
