
rule m3e9_0bb88812a92b6b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0bb88812a92b6b96"
     cluster="m3e9.0bb88812a92b6b96"
     cluster_size="1485"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="befc domaiq lollipop"
     md5_hashes="['0002d83d0b2aa9fd0f507a981d924719','0036b8b57973e79045aba71aa77bb672','02483789ae8df450ab0c6088d04ff049']"

   strings:
      $hex_string = { b68d16cb7b2a5865f7d3606ed8b7793b723f09e6f5d5cd5e3d14897343840824c577fae9eee561f3ecba706b5a32d2ea59a73ea5c8eb8fa3e15090e40e209bb8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
