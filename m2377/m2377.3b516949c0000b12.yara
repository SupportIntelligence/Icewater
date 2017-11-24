
rule m2377_3b516949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.3b516949c0000b12"
     cluster="m2377.3b516949c0000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script classic"
     md5_hashes="['00aabedb65ae10d6f7cff489c4930565','1579bf01dd776ce924403450c1c0b10a','360dc23811710fc97dcb978fb9692234']"

   strings:
      $hex_string = { 75733a5f6c6f666d61696e2e676574456c656d656e7428272e6963652d70726576696f757327297d20293b0a0909096f626a6563742e73746172742820302c20 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
