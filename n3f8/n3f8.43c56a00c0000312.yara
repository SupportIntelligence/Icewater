
rule n3f8_43c56a00c0000312
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.43c56a00c0000312"
     cluster="n3f8.43c56a00c0000312"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zdtad androidos addisplay"
     md5_hashes="['a9c8444ad1c0bd3f9143e2b4233084d23e1b5adc','6fd9bbd2abad5b8d4ebeaa3290d86ea763519c9a','19ebdcce24dc577ce1d9675f3156a80541ca81c2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.43c56a00c0000312"

   strings:
      $hex_string = { 9c89e4b88be8bdbde4bbbbe58aa1e585b3e997ade697b6e9929f290001450003454e44002b4572726f72202d2d3e204261736541637469766974792e696e666c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
