
rule m26bb_78143929c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.78143929c0000b12"
     cluster="m26bb.78143929c0000b12"
     cluster_size="45"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack amoqxaai malicious"
     md5_hashes="['d8438aa5e85c6234c38866b00cef64fb3e874062','17fae8dc0457b4823792e47506c89330d16ed9ce','0ff181163b543e5cb9f1ad259c2c040670a2d7a9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.78143929c0000b12"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
