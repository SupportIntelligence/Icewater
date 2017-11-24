
rule m3e9_6cc4159da3346d8e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6cc4159da3346d8e"
     cluster="m3e9.6cc4159da3346d8e"
     cluster_size="44"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky vbkrypt"
     md5_hashes="['109f8941c0b4939253dbb4464ab7addb','1712c3a5a7a5615f0e22fccd17354a33','abb637b49992266eb849ffaf4957a044']"

   strings:
      $hex_string = { fbd9706b6b4d440609474e676e6e6a7f838787e4e5dfd6d1c7ccb9c0c1efb6160e000000000000000000000000aeeefaf8e2726e674c0801093c5c696a6a767b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
