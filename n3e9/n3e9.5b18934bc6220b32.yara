
rule n3e9_5b18934bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5b18934bc6220b32"
     cluster="n3e9.5b18934bc6220b32"
     cluster_size="41"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['0024613e92e1460d78d8a0db022bcd9b','02fd2ef51cdd43fa6e20cd5d3638ce54','58fce079c0e54db42165242423156f14']"

   strings:
      $hex_string = { c2fa4d04f9650be8ba22e457cd5c8435a37eeb4e62f7f8a88a81d8a737d09260db90066bbfc003df86f0338d44ad463d598899e394c6086eb7557900ead7183e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
