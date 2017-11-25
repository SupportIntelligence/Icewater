
rule m3e9_611c9cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c9cc1cc000b12"
     cluster="m3e9.611c9cc1cc000b12"
     cluster_size="1313"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['0038ccaa43d5fc436a9216db715e3e6d','003c19e04aff646c0cf2df1c62142d72','0a10ff275aa7cf21ff893ca0965c230d']"

   strings:
      $hex_string = { 073d58e5ad3b88c1e70c8b72fe451a41a413a78a1ec8bed4ffc97b1dc250f96bb0da4cbd623c9e9247a6cbbb5ab41f9adc5e3b8ef7e20e208fe10b6a5267dd00 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
