
rule n3e9_1930d39d19a31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1930d39d19a31912"
     cluster="n3e9.1930d39d19a31912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cobo fareit dangerousobject"
     md5_hashes="['000b32fd872a9e5aa2b45000caf72e39','8b17c538827c84014d74f2db14e15025','dfae78008e5faf5484dd9f25256dab0f']"

   strings:
      $hex_string = { 01a51d431eea2be74da330cc45fd2fb1ec05466f726d730900ffff8bc09cfa44000f08494f6c65466f726d3c11400001c1e102cdda52d0119ea60020af3d82da }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
