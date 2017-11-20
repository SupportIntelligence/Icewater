
rule i3ed_04eb2a6929a00332
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.04eb2a6929a00332"
     cluster="i3ed.04eb2a6929a00332"
     cluster_size="4149"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="debris gamarue small"
     md5_hashes="['00027974cb85c7312d50e090d1924515','00066ee45e8494b8ed1a0295e377bf7e','01414822e61f90f9f4f41cf16984a39c']"

   strings:
      $hex_string = { 8d71fc3bf072128b0e85c97407ffd1a14032001083ee04ebea50ff151820001083254032001000595e6a0158c20c00558bec538b5d08568b750c578b7d1085f6 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
