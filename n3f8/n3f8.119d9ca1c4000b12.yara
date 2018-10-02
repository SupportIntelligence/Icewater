
rule n3f8_119d9ca1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.119d9ca1c4000b12"
     cluster="n3f8.119d9ca1c4000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bankbot adlibrary eyzuao"
     md5_hashes="['a094789ebe8590f711d772ec9e25cdea683f5772','5e6e67b79142f6180f839dae1f210214604cead8','55f4cadc17cf6a82559156f3b0e56fb94bcf7ccd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.119d9ca1c4000b12"

   strings:
      $hex_string = { 44756666244d6f64653b00174c616e64726f69642f67726170686963732f526563743b00184c616e64726f69642f67726170686963732f52656374463b00194c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
