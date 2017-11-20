
rule m2321_09197ac1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.09197ac1cc000b32"
     cluster="m2321.09197ac1cc000b32"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['043b11af43637911a0448732f6b24009','15764521b7586d6c174b0cc5bd57e78d','cb112d59e74fee741c7a279be0fad218']"

   strings:
      $hex_string = { 6eb99678d48e9203aed0acc7d8df4b6940236c590779050c2a09bb2f0dfc647574b4b625e1f14e0d2c61ee42da24b0ba6a29578f3ebdddad2d67459793d2171a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
