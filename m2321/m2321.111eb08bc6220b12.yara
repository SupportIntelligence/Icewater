
rule m2321_111eb08bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.111eb08bc6220b12"
     cluster="m2321.111eb08bc6220b12"
     cluster_size="61"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz banker"
     md5_hashes="['0092fb3dd8f56b54dd63405d8c17fe0c','01a1cfeae2d65f103337d3037b3f774d','46b6ec72be96f4ef2f751ac927ec3086']"

   strings:
      $hex_string = { cb6259fe27428baef6eddc5d9d65850305359d8c1e29948f758df7b1d7681bb0bf7a91d93f81c8ce67710f225bff36aa9869d518da6f7066a52343cf7fca55cd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
