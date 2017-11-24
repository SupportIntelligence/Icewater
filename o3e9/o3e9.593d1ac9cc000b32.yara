
rule o3e9_593d1ac9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.593d1ac9cc000b32"
     cluster="o3e9.593d1ac9cc000b32"
     cluster_size="114"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur ransom"
     md5_hashes="['02769dc15a6827a71c8eb1cc994d631f','0dad66caf29ee07ef8c5acc65a645c34','656cb94c6f4290ad21a7fb9a331c3a2b']"

   strings:
      $hex_string = { 8091ffab8192ffa2889eff9c8fa7ff939ebaff89accbff71cff8ff74c8f1ff89aacaffb97f85ffcf8962fffed6adfffcd1beffdb968bff331a0d8c351b0e3c3f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
