
rule m3f7_619c93c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.619c93c9c8000b12"
     cluster="m3f7.619c93c9c8000b12"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['1b53df7c0b7040f4fd6974ae59fb5995','9ed03c994c9f13274b9970ddf980fd6a','f202732901bc7837b6e169bc0626bec8']"

   strings:
      $hex_string = { 6577205f576964676574496e666f2827426c6f674172636869766531272c202773696465626172272c206e756c6c2c20646f63756d656e742e676574456c656d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
