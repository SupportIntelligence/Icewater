
rule n231d_29189299c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.29189299c2200b32"
     cluster="n231d.29189299c2200b32"
     cluster_size="97"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos bankbot hqwar"
     md5_hashes="['00726431416615039440440b96d799f4da89bb70','343407bb14d42bec59a3afb0af043db688ed6f26','3085e34e075fa306c0714bed82da02fa2a017a33']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.29189299c2200b32"

   strings:
      $hex_string = { e91656a93d3c35c73b2fff0baac10eb4d61833dc37b5af522745a14a967f5dc9d46253cb573f9ef099df702c3e0ffeccfa93693621c084a042b8efcfe1b3bf6b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
