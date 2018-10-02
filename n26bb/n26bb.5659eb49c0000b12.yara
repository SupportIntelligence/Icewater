
rule n26bb_5659eb49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.5659eb49c0000b12"
     cluster="n26bb.5659eb49c0000b12"
     cluster_size="196"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="filerepmalware gandcrab malicious"
     md5_hashes="['5c34aa3cb496168c3f1de3445e0b193acc09dc37','33ce1b1a1823ad4b03111800e4f07012df039012','20d0ec496a01085d15beb2633824677b26012ecb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.5659eb49c0000b12"

   strings:
      $hex_string = { 73e2fe73e2fee6d5afe6d5afe6d5af4be58778a0fa78a0fa198382fa6a92fa6a92fa6a92fa6a924be5874be58731b862c8d9cac8d9cac8d9ca5f8ce54cb0884c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
