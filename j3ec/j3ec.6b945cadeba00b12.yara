
rule j3ec_6b945cadeba00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.6b945cadeba00b12"
     cluster="j3ec.6b945cadeba00b12"
     cluster_size="429"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector acygreci infector"
     md5_hashes="['009e81edd79e688b35031215adb1df03','00df56a2fab062f6c7bc4ee24ce1491b','0859d17801b13a4031dc1b6f7b9ebaa3']"

   strings:
      $hex_string = { edeb797c8ffa4252a1626fab0c314f24233486fe6ed47b51f510fde762b14a4d6c086aee142dc2a54c2b5c6b11cb06e40cc41947919fa823ef7392e3db7e3925 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
