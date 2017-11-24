
rule n3e9_58e27ac1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.58e27ac1c4000932"
     cluster="n3e9.58e27ac1c4000932"
     cluster_size="119"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik tcfni"
     md5_hashes="['0869b83a398cdb1a7885d1fdab86b176','10daddb624b2f61f5a761f8d23c9eb64','965f9931e5b47e03b31e16d6356abdef']"

   strings:
      $hex_string = { 99dca799dda798dda793d5a289c7979ba753c1a82ac39f1ec49f1eb79b25ab5703a94806b24c00b24c00b25107b65000ba54005c84121aa1210e9e1c0fa1220f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
