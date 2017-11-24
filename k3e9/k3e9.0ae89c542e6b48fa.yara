
rule k3e9_0ae89c542e6b48fa
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0ae89c542e6b48fa"
     cluster="k3e9.0ae89c542e6b48fa"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['0c402c7fa62b0a588acd44b5dfdec790','168c6abca12151e5c70eed4864b580ab','dd911cec2a5c642a5b5430f4cb9cb9d0']"

   strings:
      $hex_string = { 70bb29794bf7667d0e3ed5b0b8e7c3cf2d933cd7e1d19b118ce09ce4836384a937df042c97af013e959ab3756ceefae65cef7465d8c8155b228a5ff4c234f672 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
