
rule m3e9_0b3a56c9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b3a56c9cc000912"
     cluster="m3e9.0b3a56c9cc000912"
     cluster_size="26"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod kazy trojandropper"
     md5_hashes="['0354d9cb7682973cfb5e26e15b58a7fc','17cf3962657b05ebf4bb77e21ac248d4','7c2cc7ee4df02ea5f41d4a4b5c2d1b45']"

   strings:
      $hex_string = { c7b3b6178ae90eeb3415e5cd25879bad429ef204fc84365d78039f1e4d49811f61d3cffdb28d6c7ebae8793e20ff777548d7fe802ddf1d749d147afbee990296 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
