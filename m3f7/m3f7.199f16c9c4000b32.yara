
rule m3f7_199f16c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.199f16c9c4000b32"
     cluster="m3f7.199f16c9c4000b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['3d04d824189ad844a3c17482f0575c8c','40c515968a338a1e6d6a37246f51c190','fd0bb4b04c74e6fa4cc6436232ce7289']"

   strings:
      $hex_string = { 643a4458496d6167655472616e73666f726d2e4d6963726f736f66742e416c706861284f7061636974793d3029262333393b3b20206d617267696e2d6c656674 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
