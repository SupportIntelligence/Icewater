
rule n3ed_63141ae992431b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.63141ae992431b32"
     cluster="n3ed.63141ae992431b32"
     cluster_size="38"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox graftor yontoo"
     md5_hashes="['09f19a33022381b7acd0aaa0072c74c1','0cc4903b07eaf624b1d5816188b56b54','6772657a65b0178271e5fd7eeab55be7']"

   strings:
      $hex_string = { 02006675636f6d69700000000000000000003020000031200000000000000000000000d0800740000000000000000000000006000000050002006675636f6d69 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
