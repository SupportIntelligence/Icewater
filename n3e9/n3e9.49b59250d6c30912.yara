
rule n3e9_49b59250d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.49b59250d6c30912"
     cluster="n3e9.49b59250d6c30912"
     cluster_size="18"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kazy badur bkdr"
     md5_hashes="['035b432ab9e83feaae8a42b4d07c5251','0e127eb4d4a204a972ca250bea2c5fd2','d717a57a7178a432f05e12acc9e4793c']"

   strings:
      $hex_string = { 61d8b05a2539fe4135d46c854adfb32691de2c2a2b48f6137bf13e99d71a580deb37656e53d1e0e643386bb4b8644bbb12fbacefc853f95424a05b734d17d0d9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
