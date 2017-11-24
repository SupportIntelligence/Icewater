
rule j3e9_24a9e265deeb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.24a9e265deeb1912"
     cluster="j3e9.24a9e265deeb1912"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="selfdel generickd upatre"
     md5_hashes="['0346a14d271b7227df66c2cc8be38541','5d6a2635e840ab138c53ab6e5d93f694','ef4c025c72fceaa15b2ac5e1d4e031a7']"

   strings:
      $hex_string = { 7e0dbf1e128274973ba65114df636e8d423f0ece4f9a85f5a063a52fa03d7b0b8ed5207fbb6e537250cff3fa4027945ff82b6c46f99103fb6f47b9ef35d1d461 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
