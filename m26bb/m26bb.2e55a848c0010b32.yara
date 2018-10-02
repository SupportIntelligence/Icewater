
rule m26bb_2e55a848c0010b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.2e55a848c0010b32"
     cluster="m26bb.2e55a848c0010b32"
     cluster_size="185"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadadmin downloadmin malicious"
     md5_hashes="['9c1b3fcb68ab9be6301bc90de021ab0bf17ca214','a2768dddaa05a9070e2fac8cfb30b4ba6b0ef4e6','2d0c066f0d43ebb9eb34b9f694da2ffda88a8377']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.2e55a848c0010b32"

   strings:
      $hex_string = { fefff3f8f4ffdeede3ffc0dbcbff99c5a9ff6cae82ff409b5fff209544ff1b9946ff1c9e47ff1f9846ff329b55ff6bb785ffa8d0b4ffd2e5daffecf4eefffcfd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
