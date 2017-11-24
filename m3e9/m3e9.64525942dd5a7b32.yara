
rule m3e9_64525942dd5a7b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.64525942dd5a7b32"
     cluster="m3e9.64525942dd5a7b32"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik emailworm"
     md5_hashes="['1d7814c10687bc4277b89f7522399af9','a93931158b80ea029f6e9b166fd023a7','d72f10bc369cfbc7b560b86e77102e10']"

   strings:
      $hex_string = { 24b1ae7198aef4ff707aff1ea0020490ae0420ad0513002414000d140015000820ad0d5800160027dcacfec1fcac300000001b17006cf4b0fbfe231cad2a460c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
