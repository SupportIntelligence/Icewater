
rule m3e9_632ee1c6d92b1916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.632ee1c6d92b1916"
     cluster="m3e9.632ee1c6d92b1916"
     cluster_size="104"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef diple"
     md5_hashes="['021c1a5ff203026a221678206fb109f2','0add987d971f38b3f019b05f6aea11a0','7d9828e77ab5bf466f245193e53c6fe6']"

   strings:
      $hex_string = { 0c050567bdbfba6dba8887861b0254d7f6f7f9f7f6cc5626000000037b767a81b7cac1c9c0cabe3c282a2a2b2827290c2a052d67bbb36e6d674c4c4b111857d4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
