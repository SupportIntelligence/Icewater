
rule n3e9_6506d2edc2810b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6506d2edc2810b12"
     cluster="n3e9.6506d2edc2810b12"
     cluster_size="2681"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="exploit lotoor gingerbreak"
     md5_hashes="['000185aeb0c2907324c1aca3db1b2450','001d982a0eb4bc2ae7a5287cbf70acdd','01da8e9381cf255b4413238ffb548dce']"

   strings:
      $hex_string = { 7c3d68c21e8cad5b8eaf1c40647f54ffc1c5b78247e494b05032b30e003e90959d18c0c3a639a346c87abcdb60913f107e87f219353a5a52d71b6a3304e073a5 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
