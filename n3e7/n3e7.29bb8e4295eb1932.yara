
rule n3e7_29bb8e4295eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.29bb8e4295eb1932"
     cluster="n3e7.29bb8e4295eb1932"
     cluster_size="67"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="guagua porntool tool"
     md5_hashes="['1337cef5a54b0e2ed1c30e3d8dc61645','174084eaab5a6f4d6f1dbc1408e96f0a','7aa5e4fed3d6193cc95f98113f8a48d3']"

   strings:
      $hex_string = { bcde79ac865b621fef24569e9f61f9ddf3bfee9f16be3bdfb31d80ce0af83ef5967f21bfd99cbefcb68af2dbcc3bf2bbf0f23938fec90761c97fbb83c9efa9a3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
