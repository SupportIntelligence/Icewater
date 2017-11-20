
rule m3ed_29372fb9c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.29372fb9c6220b12"
     cluster="m3ed.29372fb9c6220b12"
     cluster_size="2635"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox kranet siggen"
     md5_hashes="['000668556861a9e5ba09796156090ca5','0028535c0f3ed87f7724ca50f31d7160','0183c734b0d6873e78e8a4fa2bc78f0f']"

   strings:
      $hex_string = { 4d1083c7048939eb0b79064e89750ceb038d5e013b5d0c7ebe5f5e33c985c00f94c15b8bc15dc38bff558bec5185f67450803e00744b6818b4011056e829b1ff }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
