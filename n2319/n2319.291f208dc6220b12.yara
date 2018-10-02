
rule n2319_291f208dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.291f208dc6220b12"
     cluster="n2319.291f208dc6220b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner coinhive coinminer"
     md5_hashes="['7945807fc2293b8e3ee911e310bc742297546736','a0c94c0330c55af8aeab3785a03d038ff8fd98c0','f55e016fe4b0fc724f8ed13290d714abeead1c2f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.291f208dc6220b12"

   strings:
      $hex_string = { 6774687c7c6e2e6572726f722822496e76616c696420584d4c3a20222b62292c637d3b7661722048623d2f232e2a242f2c49623d2f285b3f265d295f3d5b5e26 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
