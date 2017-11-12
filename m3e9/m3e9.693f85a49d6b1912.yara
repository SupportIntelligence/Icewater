
rule m3e9_693f85a49d6b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f85a49d6b1912"
     cluster="m3e9.693f85a49d6b1912"
     cluster_size="351"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['0484adb9c15c8d68439dbd3b38f38e22','05312105c9d22045dbea147b0f5a8e70','34fa40179be7ef1070ac587d12bea56a']"

   strings:
      $hex_string = { 0f90bd918fefd6c2a89ce3a9abeb7b568e3085de9163c17a41bc4edda433a4bfbdd313954b85baad196d0b19befe8270d794c1b57f48dff7da5e4ff7d498de07 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
