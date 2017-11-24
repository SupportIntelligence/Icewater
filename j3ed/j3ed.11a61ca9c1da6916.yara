
rule j3ed_11a61ca9c1da6916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ed.11a61ca9c1da6916"
     cluster="j3ed.11a61ca9c1da6916"
     cluster_size="7"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ursu malicious proxy"
     md5_hashes="['0c87c7b6f54d62750fcb7f18dbc60f09','3d44116b4400d4250d4e0afefded1fa2','dfface1e42dc68fabe001d8749851238']"

   strings:
      $hex_string = { d152ba6443b25cb8ce510010408910b26686d6887004b26186d688700851b92a19751787d12910598b152e1100102850065aeb05eb62ffd0c35356575bbfa05d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
