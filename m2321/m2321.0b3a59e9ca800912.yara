
rule m2321_0b3a59e9ca800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b3a59e9ca800912"
     cluster="m2321.0b3a59e9ca800912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod kazy eydrop"
     md5_hashes="['3bd49d40fa6575bf5ab341c8d0723644','4a0ada55d630196070f9843fdd607f30','c43567c8717657903fdd3827d198e6e9']"

   strings:
      $hex_string = { c7b3b6178ae90eeb3415e5cd25879bad429ef204fc84365d78039f1e4d49811f61d3cffdb28d6c7ebae8793e20ff777548d7fe802ddf1d749d147afbee990296 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
