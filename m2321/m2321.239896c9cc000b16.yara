
rule m2321_239896c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.239896c9cc000b16"
     cluster="m2321.239896c9cc000b16"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['059f6b2fca658702757c792d3ee7b24a','0a792b6a09074a6a1234ab874db344f7','e6dc42e888e34e956681b4d5ee98abe0']"

   strings:
      $hex_string = { 83c20da5fe9acc5d3dbc78d0eeef91fa95fcb344e6d7f2e0779e0a6e1907086a495bf1a60c807a5cc7ae5fd50febd1c88bc3a35e386f8768b7546127ad2aed3e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
