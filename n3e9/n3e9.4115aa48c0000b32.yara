
rule n3e9_4115aa48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4115aa48c0000b32"
     cluster="n3e9.4115aa48c0000b32"
     cluster_size="120"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky diple"
     md5_hashes="['05dabd89f5bd72f22e8c199d97ddf840','091b6f62b2cd2766468a463b95a24249','9b03c5e8dcfceecfbf20f82dfcb1a0a6']"

   strings:
      $hex_string = { 2d45bcc8daf5d2c77875b0989e940b0565dff1f1f5f1efdd4b2200000008082c3a4dc1cad2dadadfd24128040606060606293b5378ddcb787773b198959c1602 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
