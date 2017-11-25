
rule k3e9_211cfac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.211cfac1c4000b12"
     cluster="k3e9.211cfac1c4000b12"
     cluster_size="4646"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor bgtuw darkkomet"
     md5_hashes="['000581fc1944412e45880cd9d5d78c5d','0011ee54fb4228d0cbb1d6529e8702f4','00cae18a5c7e6c60b2e7c11967b87c72']"

   strings:
      $hex_string = { 85c0743a3bf07322837dfc000f84b10300000fb602ff4dfc8bced3e04283c6088955f803d83b774872de8b4f48b801000000d3e04823c3014740d3eb2bf1c707 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
