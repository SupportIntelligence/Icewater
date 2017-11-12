
rule o3e7_14935898dee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.14935898dee31912"
     cluster="o3e7.14935898dee31912"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious installmonstr engine"
     md5_hashes="['46de2da99e0400ca2296e41932175c0b','ac05f06a0c8c0d2ae3dd13eb9e5a135f','f7b4bbcfe2c9d8c67726eeebf3d84124']"

   strings:
      $hex_string = { 3abb3ed7c68b6550ef9ae7119d07b0745c27c7bd2a1ca82ce414620c18aa33605b3197a6f1e109f822faac723529b8faf22b900e6cd9e8a479e58c1b13032067 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
