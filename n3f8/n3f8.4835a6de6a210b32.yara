
rule n3f8_4835a6de6a210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.4835a6de6a210b32"
     cluster="n3f8.4835a6de6a210b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="sandr androidos kasandra"
     md5_hashes="['d9b5f2b0b95d9927975229c02cd88032203570bb','9569fdeea0fddb06617faaa4272459963f50e8fa','261ff1fef65158e0a61aca75247f10d3d107305e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.4835a6de6a210b32"

   strings:
      $hex_string = { e30307000a04b1431504b4426e20900048006e10e60307000a047b4482445275a7011506803fc6657f558226c8656e3094004805547485016e30f30834025472 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
