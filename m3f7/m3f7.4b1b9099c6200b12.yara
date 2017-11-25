
rule m3f7_4b1b9099c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.4b1b9099c6200b12"
     cluster="m3f7.4b1b9099c6200b12"
     cluster_size="15"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker autolike script"
     md5_hashes="['03cb14aa4115cf5a6438bacbb46087ba','0c14a3d8558012fd99d78bed62b31c4a','ecf9c2e0d5d31b8e05a1a2d6cef8cf21']"

   strings:
      $hex_string = { 4143626f2f5038505f53474564687a492f7333362f32312e676966272f3e22293b0a74686554657874203d20746865546578742e7265706c616365282f622d5c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
