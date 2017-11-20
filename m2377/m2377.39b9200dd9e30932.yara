
rule m2377_39b9200dd9e30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.39b9200dd9e30932"
     cluster="m2377.39b9200dd9e30932"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['04971423c236c7ef25c69abf2d2c8d14','094a0b0003ddc0723405d58cad41e63f','c6a1cec9cc8131bcd8fa2a3c3a10eed2']"

   strings:
      $hex_string = { 44333638374644414439364438343343303546373342374336453042343133373043314139303536384132313936393732373932453845453242463130423534 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
