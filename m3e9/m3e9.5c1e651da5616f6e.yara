
rule m3e9_5c1e651da5616f6e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5c1e651da5616f6e"
     cluster="m3e9.5c1e651da5616f6e"
     cluster_size="55"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="diple vobfus chinky"
     md5_hashes="['05c01949b3bd10809fd17cf8aee6fa44','105c9424de3a510e15b70da3ee94393e','ace179934531a3d59bfa92cb3ea49325']"

   strings:
      $hex_string = { 506a106880080000e81bb8fdff83c41c8d45d8894598c74590034000008d55908b45a033c92b4814c1e1048b45a08b400c03c8e8e8b6fdff83658800c7458002 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
