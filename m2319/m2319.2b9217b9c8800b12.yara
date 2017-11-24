
rule m2319_2b9217b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b9217b9c8800b12"
     cluster="m2319.2b9217b9c8800b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['8f4459c41302ff30462e7fe6c220fd03','b0c25511c96926b0845d26edda9563a8','fa4bb7314484c82887ba7ce4091ec8db']"

   strings:
      $hex_string = { 66795962544d6f54705f452f55487a476c43534b6736492f41414141414141424c71382f527a4368544944325731302f7337322d632f70756d706b696e2d616e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
