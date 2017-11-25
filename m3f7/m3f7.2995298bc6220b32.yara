
rule m3f7_2995298bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2995298bc6220b32"
     cluster="m3f7.2995298bc6220b32"
     cluster_size="16"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script cloud"
     md5_hashes="['0554e45b44d79bc3bf0e3028f220c178','0bd05ad8bf9b50e4df016878941144a8','fca38181a753c7d511795289291295e8']"

   strings:
      $hex_string = { 6774687c7c6e2e6572726f722822496e76616c696420584d4c3a20222b62292c637d3b7661722048623d2f232e2a242f2c49623d2f285b3f265d295f3d5b5e26 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
