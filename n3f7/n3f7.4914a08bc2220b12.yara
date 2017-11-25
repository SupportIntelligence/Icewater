
rule n3f7_4914a08bc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.4914a08bc2220b12"
     cluster="n3f7.4914a08bc2220b12"
     cluster_size="44"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['072f77aa20354dd17a2c5d8b63c615b1','0dd0c05ce6dab9cfb748694cf34695cc','5ed025b7547c32b7917820cd3e36b43c']"

   strings:
      $hex_string = { 77205f576964676574496e666f2827426c6f674172636869766531272c202773696465626172272c206e756c6c2c20646f63756d656e742e676574456c656d65 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
