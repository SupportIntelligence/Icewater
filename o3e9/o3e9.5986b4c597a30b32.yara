
rule o3e9_5986b4c597a30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.5986b4c597a30b32"
     cluster="o3e9.5986b4c597a30b32"
     cluster_size="126"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="strictor dealply malicious"
     md5_hashes="['012d29374c9bc0072b6a0f675fbbcb9b','034594fbcdd1801455ced12f9959f564','1be22f5e749469cfe4fd6c7ea00888f2']"

   strings:
      $hex_string = { 00190049006e00760061006c00690064002000540069006d0065006f00750074002000760061006c00750065003a0020002500730030005300700069006e0043 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
