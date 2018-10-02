
rule k2319_1b1916b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1b1916b9c8800b12"
     cluster="k2319.1b1916b9c8800b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script adinject"
     md5_hashes="['a840a13f78c486c4e32026bdc68f8339a4f220f8','0810204feda31af757c361d7ba67abf1c24078d2','171a19669bea6f43f128187be750d0b48f5f4507']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1b1916b9c8800b12"

   strings:
      $hex_string = { 3f2830783134392c313139293a2831302e2c32372e334531292929627265616b7d3b76617220423679343d7b27593169273a66756e6374696f6e286e2c6b297b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
