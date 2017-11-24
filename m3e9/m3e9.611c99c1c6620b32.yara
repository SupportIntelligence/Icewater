
rule m3e9_611c99c1c6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c99c1c6620b32"
     cluster="m3e9.611c99c1c6620b32"
     cluster_size="52"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef diple"
     md5_hashes="['005b7db978ed20d8e728132949946e2e','199af45d430e6403a115c30047f44e46','ae26916e471ecc2472c39abbb8e61a28']"

   strings:
      $hex_string = { 9c508d45ac508d45bc508d45cc506a04e8ca1effff83c414c3c3668b45dc8b4de064890d000000005f5e5bc9c20800e8cf1effff558bec83ec1868a62f400064 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
