
rule m3e9_13946a44c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13946a44c0000932"
     cluster="m3e9.13946a44c0000932"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="wabot backdoor shellini"
     md5_hashes="['3977a9e1e833a574845c8c9cd76412f8','9e299c403ba0904d578399a6f0c68b31','cc8d0ba0a1c381e61704068159410264']"

   strings:
      $hex_string = { 6162636465666768696a6b6c6d6e6f707172737475767778797a2d5f2e3132333435363738393000558bec51b93c0000006a006a004975f951874dfc53565789 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
