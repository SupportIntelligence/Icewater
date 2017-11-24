
rule k3e9_191c9fa9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.191c9fa9ca000b12"
     cluster="k3e9.191c9fa9ca000b12"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['32b1ef9077363ffa6c3b0bcc71a732b3','4393aeb2a386d340c39587fc274f2598','c7f77d48ae7f2ff0cdf6d8c4f4ac0303']"

   strings:
      $hex_string = { 456e88b09dfe5348f116b5c5efc475273d433f57ca0a085a8696064d44e6dcf40f6811a5ca668e5eee9bb67cc9cc945fd24dcdc0d5d1790da89c9fdff21b4cd3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
