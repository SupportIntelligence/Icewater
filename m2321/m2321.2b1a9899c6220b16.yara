
rule m2321_2b1a9899c6220b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b1a9899c6220b16"
     cluster="m2321.2b1a9899c6220b16"
     cluster_size="4"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut midie shodi"
     md5_hashes="['0a5cc7682f665262f4d2dd9f43dbb1cd','157f396aa1f52feea109a453c437ac14','f38e11aaa3dee3aeb6c993a570e68f9b']"

   strings:
      $hex_string = { e5a7c46b082d15cdb505f4d19e3b595404aac15bcbf53767e3530bb613ab413d61767c4c4a3c63d5b4506c8f2e9a56b1333123c362a268b2fe88eac851486e3f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
