
rule i3ed_04eb2a4929a08132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.04eb2a4929a08132"
     cluster="i3ed.04eb2a4929a08132"
     cluster_size="76"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="debris gamarue zusy"
     md5_hashes="['04ed728bc6b4c86a1d7e1d0a022d5334','08afba29f75a56762b945e2e2f4052b7','adc0f56f340ec8e3f4cd47e712642211']"

   strings:
      $hex_string = { 8d71fc3bf072128b0e85c97407ffd1a14032001083ee04ebea50ff151820001083254032001000595e6a0158c20c00558bec538b5d08568b750c578b7d1085f6 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
