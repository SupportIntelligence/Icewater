
rule m3e9_2b1d6b721ec30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2b1d6b721ec30b12"
     cluster="m3e9.2b1d6b721ec30b12"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi pronny"
     md5_hashes="['7dced6e76fdd05a74af67566fa9b5d4e','a0b7dd7e03494699b50309482ba79592','ff9c4eb2e0037a1a40838d80950d73fa']"

   strings:
      $hex_string = { 520460f74dc0f60340fc8f50f702000450f70708000c05fdfe54f7940800b80507080060022413000d200014000450f75a6c2cf799080064062f54f7000f2818 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
