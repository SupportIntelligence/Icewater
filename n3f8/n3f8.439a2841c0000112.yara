
rule n3f8_439a2841c0000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.439a2841c0000112"
     cluster="n3f8.439a2841c0000112"
     cluster_size="145"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zdtad androidos inoco"
     md5_hashes="['43078f4c0e34f591ff4919391c2a5d22bb9825d5','3d647026df11224dfe94c5f748b8095a96bac8f2','8aef943d01bb90ceee94e9ddab7f53ef8bc98756']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.439a2841c0000112"

   strings:
      $hex_string = { 9c89e4b88be8bdbde4bbbbe58aa1e585b3e997ade697b6e9929f290001450003454e44002b4572726f72202d2d3e204261736541637469766974792e696e666c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
