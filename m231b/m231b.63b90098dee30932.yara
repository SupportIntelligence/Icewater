
rule m231b_63b90098dee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.63b90098dee30932"
     cluster="m231b.63b90098dee30932"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit script html"
     md5_hashes="['03e3643f7fdfda0fe91d0b9d284cb408','6014999df725ade51c11946e0f0ea807','98d3762ac2c3d2199b9cdc6e376a872c']"

   strings:
      $hex_string = { 6e672e46696c6553797374656d4f626a65637422290d0d0a44726f7050617468203d2046534f2e4765745370656369616c466f6c646572283229202620225c22 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
