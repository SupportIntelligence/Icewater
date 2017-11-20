
rule j3f0_291ee5acdee30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.291ee5acdee30b32"
     cluster="j3f0.291ee5acdee30b32"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious malob"
     md5_hashes="['24da1b296ddd90c3fdcc1cf00cd26dba','38f61a00a86fcde3c63c106dc7e9899c','fd379768033c7b3daedbfd92cef855d4']"

   strings:
      $hex_string = { a804f31fbd58051bdf8550495302d036745c04bf3715b98bd204af9a14ffd22e2106fb1ae4620cffd2aeb0b8b8688020b5388200bd01e00b7a89da701908105f }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
