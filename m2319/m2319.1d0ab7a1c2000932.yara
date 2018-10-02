
rule m2319_1d0ab7a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1d0ab7a1c2000932"
     cluster="m2319.1d0ab7a1c2000932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['84ba9847ba1672606c7532086890cfdff1f8f969','49d35e3c1114f192e6a8329efd5355621cbd8924','c9ed947128cabbbfc6774dda7276e1dca654c752']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1d0ab7a1c2000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
