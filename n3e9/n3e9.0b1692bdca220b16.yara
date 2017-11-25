
rule n3e9_0b1692bdca220b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b1692bdca220b16"
     cluster="n3e9.0b1692bdca220b16"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi dealply malicious"
     md5_hashes="['075731f81c7cc382d9865fba794e7215','810e76a72f79781a4509692cb09ec314','a42460551f6eceef6bed636ab69a9d12']"

   strings:
      $hex_string = { 3c7fff1e1c7fff1f0c7fff0f847fff8fc0ffff87e0ffffc1e1ffffe003fffff007fffffc1fffff040041006c0074002b00200043006c006900700062006f0061 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
