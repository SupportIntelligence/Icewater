
rule n3e9_11152f4bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.11152f4bc6220b12"
     cluster="n3e9.11152f4bc6220b12"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur gena"
     md5_hashes="['59b90151747093ce04c205f74faa49b4','aaaddb96a3c64cab156fd7b0c2cd97be','f528a5e3a4bdac20ebfa8d568a9f69bb']"

   strings:
      $hex_string = { 010001002020000002002000a8100000010050414444494e47585850414444494e4750414444494e47585850414444494e4750414444494e4758585041444449 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
