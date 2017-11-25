
rule k2321_09b26112d9db4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09b26112d9db4912"
     cluster="k2321.09b26112d9db4912"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['52503f0646cf84b06378806779f5db7f','7da4e9e23a8463a28d1592d3d8be5627','fb6b6f15ef86dee28cbe3972f398df4f']"

   strings:
      $hex_string = { 35da6d2519d9d87c5f62aa84ba028d94cbbf2d52b60403ea1768b57200faa994fea3e85b9289c56a46c12ef0d2b70693a5381b56292672f4fbbc440e5d3ee9f1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
