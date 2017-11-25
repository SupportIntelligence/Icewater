
rule n3e9_2b542b1dca210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b542b1dca210b32"
     cluster="n3e9.2b542b1dca210b32"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply symmi malicious"
     md5_hashes="['398001dff6ccc5ea82e6da257c1aceea','39fcf0270fe4a3192aae2afe48dc33c3','ee33e71fb995175c542de9a97dd42869']"

   strings:
      $hex_string = { 000b00590065007300200074006f002000260041006c006c00040042006b005300700003005400610062000300450073006300050045006e0074006500720005 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
