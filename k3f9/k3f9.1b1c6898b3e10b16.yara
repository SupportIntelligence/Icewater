
rule k3f9_1b1c6898b3e10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.1b1c6898b3e10b16"
     cluster="k3f9.1b1c6898b3e10b16"
     cluster_size="871"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta hllp malicious"
     md5_hashes="['002f7cd673ebffeeb0a704c65b5dbddf','011ddf674449aa1668f1d6bbe5cbb9f5','04681610c5a2a470013210857e1758bd']"

   strings:
      $hex_string = { 022c208a57ff88d480ec6180fc19770380ea20b40029d0750580fa0075d25e5fc38d4000979283c9ff31c039f87406f2ae484829c889d7c356e83afbffff89d6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
