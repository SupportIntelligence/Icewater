
rule i3ec_06b48b2cc36b0b34
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ec.06b48b2cc36b0b34"
     cluster="i3ec.06b48b2cc36b0b34"
     cluster_size="4"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['49a157de2f17b6d878fb15e00d77a72d','4cee9fe5c97b9abc2f7fe78debe0b12b','d46117ec884c5c0538137fa0cd7d1a2c']"

   strings:
      $hex_string = { af3f4ab29a2ca22ddfb97afcaeb9397efde68bf7e49fe2de75c6ff088f5c5276ddadf3ff33fd723c5b1f36f7f60da65da3e5eec1913dc3a5071e1f2af5a7c9b1 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
