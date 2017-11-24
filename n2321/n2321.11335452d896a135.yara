
rule n2321_11335452d896a135
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.11335452d896a135"
     cluster="n2321.11335452d896a135"
     cluster_size="11"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['4b4e4720f38361a2b8405b473ce57170','4f9da927fde14aee82d31b3e62fcdac3','d184a2f23f61195aef0f3e1f7d3756e8']"

   strings:
      $hex_string = { a55536e761ce29b03571ff9caaa7e49d25381b150c73b33d115fa2e30a92d9cad2028e44e27c64fc7fec5d0f7054c779df930ed0393227bbb8a12e89cf338a6b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
