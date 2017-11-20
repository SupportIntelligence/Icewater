
rule k3e9_6eb2c290daf4cc9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6eb2c290daf4cc9a"
     cluster="k3e9.6eb2c290daf4cc9a"
     cluster_size="3706"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="linkular linkun downware"
     md5_hashes="['00035a03071d419ffd5b544cd0593f80','000f381bdd6402821f13cae293e89066','00cf599cb7a260f3228d281ce51f89a5']"

   strings:
      $hex_string = { 64b02ed4cc8f61849c3dc12c7b8b4b3f1703e19a46b11001f4d890a7d33b5c38427299532b284f240d5ec8eeecb7899866090b55a9fdc447042de426434ca1b6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
