
rule k3e9_332d36c126a7cb16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.332d36c126a7cb16"
     cluster="k3e9.332d36c126a7cb16"
     cluster_size="223"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="munlight amvu badclean"
     md5_hashes="['005cf0a8f5a8489290cd84d2506cea7e','02ea5dcdd543d11d4e853207b9ee1d85','18eb1aef5a052a474f0e26f74d27539f']"

   strings:
      $hex_string = { c92ef76766ccf421208a7e94096e4e1462c5d80d0e7887868837f3e4774d1efe7336e52bb015b32600e05c8219f83ac07c3839cf709ee88155aebc10ff1c5f8f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
