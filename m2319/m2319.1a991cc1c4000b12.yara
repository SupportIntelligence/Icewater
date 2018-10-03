
rule m2319_1a991cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1a991cc1c4000b12"
     cluster="m2319.1a991cc1c4000b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['52cf6e0c8a12df475899bb9801cd145cd111552e','ca6e8a898e2ed037dadf5d787af06fe1770ece79','8054b2ed8af49d2a26e487bcbba1a7d01c816fb4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1a991cc1c4000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
