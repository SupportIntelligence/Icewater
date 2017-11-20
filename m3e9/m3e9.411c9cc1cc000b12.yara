
rule m3e9_411c9cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411c9cc1cc000b12"
     cluster="m3e9.411c9cc1cc000b12"
     cluster_size="258"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['0092301d77144921a099b6c9c52416f8','0123cfcc2b31d0b45b6398a3216b72e8','18ecaabdf40e412cc23a0b0386fb84af']"

   strings:
      $hex_string = { 073d58e5ad3b88c1e70c8b72fe451a41a413a78a1ec8bed4ffc97b1dc250f96bb0da4cbd623c9e9247a6cbbb5ab41f9adc5e3b8ef7e20e208fe10b6a5267dd00 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
