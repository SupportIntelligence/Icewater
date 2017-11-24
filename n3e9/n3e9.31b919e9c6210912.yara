
rule n3e9_31b919e9c6210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31b919e9c6210912"
     cluster="n3e9.31b919e9c6210912"
     cluster_size="26"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy farfli backdoor"
     md5_hashes="['107a8131935b27dbee2b598f946961ea','15755572ab7cf8a2ff22b1820686956a','9691494da5df0a3b7d607c178a862eb0']"

   strings:
      $hex_string = { 7fe98b4d143bd388187c12803f357c0deb03c600304880383974f7fe00803e317505ff4104eb158d7e0157e8fae0fdff40505756e89189feff83c41033c05f5e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
