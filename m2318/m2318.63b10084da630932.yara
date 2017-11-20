
rule m2318_63b10084da630932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.63b10084da630932"
     cluster="m2318.63b10084da630932"
     cluster_size="244"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['056e6cc1aa3a4a0a5dc66191ac0c9c99','0775b42b19d189844bb105becf04d512','1438e05358f11ea451482a85330ff728']"

   strings:
      $hex_string = { 6e672e46696c6553797374656d4f626a65637422290d0a44726f7050617468203d2046534f2e4765745370656369616c466f6c646572283229202620225c2220 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
