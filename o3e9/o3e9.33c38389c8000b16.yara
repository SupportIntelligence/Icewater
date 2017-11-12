
rule o3e9_33c38389c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.33c38389c8000b16"
     cluster="o3e9.33c38389c8000b16"
     cluster_size="6079"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadsponsor unwanted dlsponsor"
     md5_hashes="['0002f83a1528eeaae6be64778c29800f','0007222d6a72d19ff0e0dc244fcbc430','00a587e3234f9d83724471ecbcb8588c']"

   strings:
      $hex_string = { 261b2db3d2949d012012a9871a824d2f3da167efdcb022b83914a6fcc91fb47a625f8ed1470c44582e1c61cd03bf16594c63cf8db7319673084bc217770ea7ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
