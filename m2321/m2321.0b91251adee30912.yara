
rule m2321_0b91251adee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b91251adee30912"
     cluster="m2321.0b91251adee30912"
     cluster_size="5"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery emotet pemalform"
     md5_hashes="['74f281813aed920037c8f1f8088db013','93d96434b30ab5b3c0a46d4ccbd4492f','c74aeb2dadc5e4ad51e131966aa58739']"

   strings:
      $hex_string = { 8aa61dd1213597d36f0add25f45bd5fa89cde955732ebf712cf65001b7cbaa663881d185fee434390253951bce9a6e887f9128e3df695478c3b3c80eab7bec64 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
