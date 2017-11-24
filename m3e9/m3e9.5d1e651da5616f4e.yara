
rule m3e9_5d1e651da5616f4e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5d1e651da5616f4e"
     cluster="m3e9.5d1e651da5616f4e"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky diple"
     md5_hashes="['665cf1575bbfed7ae86120973b703139','a452249bfbc20e6387ff58faf3314f27','fe15ce516b6c3acd1d8af8169f200dab']"

   strings:
      $hex_string = { 506a106880080000e81bb8fdff83c41c8d45d8894598c74590034000008d55908b45a033c92b4814c1e1048b45a08b400c03c8e8e8b6fdff83658800c7458002 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
