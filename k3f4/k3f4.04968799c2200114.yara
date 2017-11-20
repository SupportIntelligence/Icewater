
rule k3f4_04968799c2200114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.04968799c2200114"
     cluster="k3f4.04968799c2200114"
     cluster_size="31"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor bkdr"
     md5_hashes="['1a223ac8fbc7eaacf27152439e8d9ec8','280cc4727b4881f77227d680d662d00e','d423e7a76d83811187520fc0faac50f0']"

   strings:
      $hex_string = { 312e302e302e3022206e616d653d224d794170706c69636174696f6e2e617070222f3e0d0a20203c7472757374496e666f20786d6c6e733d2275726e3a736368 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
