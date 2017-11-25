
rule n3ed_631498e996c31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.631498e996c31932"
     cluster="n3ed.631498e996c31932"
     cluster_size="37"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox graftor razy"
     md5_hashes="['06073dfe3e77f96b2cb5f65e40576568','0ae3d031a40eff05275f95b2c8d2b82b','7fb7725bb48f4ed8863d1790d9e1bbde']"

   strings:
      $hex_string = { 01400000636d70736400000000000000000000000020111200201212000000000080000000fc000000100a000010140000000000020000000110000074657374 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
